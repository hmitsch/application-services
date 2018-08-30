/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use rusqlite::{Connection, types::{ToSql, FromSql}, Row, Transaction};
use std::time::SystemTime;
use std::path::Path;
use std::collections::HashSet;
use error::*;
use schema;
use login::{LocalLogin, MirrorLogin, Login, SyncStatus, SyncLoginData};
use sync::{self, ServerTimestamp, IncomingChangeset, Store, OutgoingChangeset, Payload};
use util;

pub const MAX_VARIABLE_NUMBER: usize = 999;

pub struct LoginDb {
    db: Connection,
}

// In PRAGMA foo='bar', `'bar'` must be a constant string (it cannot be a
// bound parameter), so we need to escape manually. According to
// https://www.sqlite.org/faq.html, the only character that must be escaped is
// the single quote, which is escaped by placing two single quotes in a row.
fn escape_string_for_pragma(s: &str) -> String {
    s.replace("'", "''")
}

impl LoginDb {
    pub fn with_connection(db: Connection, encryption_key: Option<&str>) -> Result<Self> {
        let encryption_pragmas = if let Some(key) = encryption_key {
            // TODO: We probably should support providing a key that doesn't go
            // through PBKDF2 (e.g. pass it in as hex, or use sqlite3_key
            // directly. See https://www.zetetic.net/sqlcipher/sqlcipher-api/#key
            // "Raw Key Data" example. Note that this would be required to open
            // existing iOS sqlcipher databases).
            format!("PRAGMA key = '{}';", escape_string_for_pragma(key))
        } else {
            "".to_owned()
        };

        // `temp_store = 2` is required on Android to force the DB to keep temp
        // files in memory, since on Android there's no tmp partition. See
        // https://github.com/mozilla/mentat/issues/505. Ideally we'd only
        // do this on Android, or allow caller to configure it.
        let initial_pragmas = format!("
            {}
            PRAGMA temp_store = 2;
        ", encryption_pragmas);

        db.execute_batch(&initial_pragmas)?;

        let mut res = Self { db };
        schema::init(&mut res)?;
        Ok(res)
    }

    pub fn open(path: impl AsRef<Path>, encryption_key: Option<&str>) -> Result<Self> {
        Ok(Self::with_connection(Connection::open(path)?, encryption_key)?)
    }

    pub fn open_in_memory(encryption_key: Option<&str>) -> Result<Self> {
        Ok(Self::with_connection(Connection::open_in_memory()?, encryption_key)?)
    }

    pub fn vacuum(&self) -> Result<()> {
        self.execute("VACUUM")?;
        Ok(())
    }

    pub fn execute_all(&self, stmts: &[&str]) -> Result<()> {
        for sql in stmts {
            self.execute(sql)?;
        }
        Ok(())
    }

    #[inline]
    pub fn execute(&self, stmt: impl AsRef<str>) -> Result<usize> {
        Ok(self.do_exec(stmt.as_ref(), &[], false)?)
    }

    #[inline]
    pub fn execute_cached(&self, stmt: impl AsRef<str>) -> Result<usize> {
        Ok(self.do_exec(stmt.as_ref(), &[], true)?)
    }

    #[inline]
    pub fn execute_with_args(&self, stmt: impl AsRef<str>, params: &[&ToSql]) -> Result<usize> {
        Ok(self.do_exec(stmt.as_ref(), params, false)?)
    }

    #[inline]
    pub fn execute_cached_with_args(&self, stmt: impl AsRef<str>, params: &[&ToSql]) -> Result<usize> {
        Ok(self.do_exec(stmt.as_ref(), params, true)?)
    }

    fn do_exec(&self, sql: &str, params: &[&ToSql], cache: bool) -> Result<usize> {
        let res = if cache {
            self.db.prepare_cached(sql)
                   .and_then(|mut s| s.execute(params))
        } else {
            self.db.execute(sql, params)
        };
        if let Err(e) = &res {
            warn!("Error running SQL {}. Statement: {:?}", e, sql);
        }
        Ok(res?)
    }

    pub fn query_one<T: FromSql>(&self, sql: &str) -> Result<T> {
        let res: T = self.db.query_row(sql, &[], |row| row.get(0))?;
        Ok(res)
    }

    // Note that there are several differences between these and `self.db.query_row`: it returns
    // None and not an error if no rows are returned, it allows the function to return a result, etc
    pub fn query_row_cached<T>(&self, sql: &str, args: &[&ToSql], f: impl FnOnce(&Row) -> Result<T>) -> Result<Option<T>> {
        let mut stmt = self.db.prepare_cached(sql)?;
        let res = stmt.query(args);
        if let Err(e) = &res {
            warn!("Error executing query: {}. Query: {}", e, sql);
        }
        let mut rows = res?;
        match rows.next() {
            Some(result) => Ok(Some(f(&result?)?)),
            None => Ok(None),
        }
    }

    // cached and uncached stmt types are completely different so we can't remove the duplication
    // between query_row_cached and query_row... :/
    pub fn query_row<T>(&self, sql: &str, args: &[&ToSql], f: impl FnOnce(&Row) -> Result<T>) -> Result<Option<T>> {
        let mut stmt = self.db.prepare(sql)?;
        let res = stmt.query(args);
        if let Err(e) = &res {
            warn!("Error executing query: {}. Query: {}", e, sql);
        }
        let mut rows = res?;
        match rows.next() {
            Some(result) => Ok(Some(f(&result?)?)),
            None => Ok(None),
        }
    }

    fn mark_mirror_overridden(&self, guid: &str) -> Result<()> {
        self.execute_cached_with_args("
            UPDATE loginsM SET
            is_overridden = 1
            WHERE guid = ?
        ", &[&guid as &ToSql])?;
        Ok(())
    }
}

// login specific stuff.

impl LoginDb {

    pub fn have_synced_logins(&self) -> Result<bool> {
        Ok(self.query_one::<i64>(&*ANY_SYNCED_SQL)? != 0)
    }

    fn mark_as_synchronized(&mut self, guids: &[&str], ts: ServerTimestamp) -> Result<()> {
        util::each_chunk(guids, |chunk, _| {
            self.execute_with_args(
                &format!("DELETE FROM {mirror_table} WHERE guid IN ({vars})",
                         mirror_table = schema::MIRROR_TABLE_NAME,
                         vars = util::sql_vars(chunk.len())),
                chunk
            )?;

            self.execute_with_args(
                &format!("
                    INSERT OR IGNORE INTO {mirror_table} (
                        {common_cols}, is_overridden, server_modified
                    )
                    SELECT {common_cols}, 0, {modified_ms_i64}
                    FROM {local_table}
                    WHERE guid IN ({vars})",
                    common_cols = schema::COMMON_COLS,
                    mirror_table = schema::MIRROR_TABLE_NAME,
                    local_table = schema::LOCAL_TABLE_NAME,
                    modified_ms_i64 = ts.as_millis() as i64,
                    vars = util::sql_vars(chunk.len())),
                chunk
            )?;

            self.execute_with_args(
                &format!("DELETE FROM {local_table} WHERE guid IN ({vars})",
                         local_table = schema::MIRROR_TABLE_NAME,
                         vars = util::sql_vars(chunk.len())),
                chunk
            )?;
            Ok(())
        })?;
        self.set_last_sync(ts)?;
        Ok(())
    }

    // Fetch all the data for the provided IDs.
    // TODO: Might be better taking a fn instead of returning all of it... But that func will likely
    // want to insert stuff while we're doing this so ugh.
    fn fetch_login_data(&self, records: &[(sync::Payload, ServerTimestamp)]) -> Result<Vec<SyncLoginData>> {
        let mut sync_data = Vec::with_capacity(records.len());
        {
            let mut seen_ids: HashSet<String> = HashSet::with_capacity(records.len());
            for incoming in records.iter() {
                if seen_ids.contains(&incoming.0.id) {
                    throw!(ErrorKind::DuplicateGuid(incoming.0.id.to_string()))
                }
                seen_ids.insert(incoming.0.id.clone());
                sync_data.push(SyncLoginData::from_payload(incoming.0.clone(), incoming.1)?);
            }
        }

        util::each_chunk_mapped(&records, |r| &r.0.id as &ToSql, |chunk, offset| {
            // pairs the bound parameter for the guid with an integer index.
            let values_with_idx = util::repeat_display(chunk.len(), ",", |i, f| write!(f, "({},?)", i + offset));
            let query = format!("
                WITH to_fetch(guid_idx, fetch_guid) AS (VALUES {vals})
                SELECT
                    {common_cols},
                    is_overridden,
                    server_modified,
                    NULL as local_modified,
                    NULL as is_deleted,
                    NULL as sync_status,
                    1 as is_mirror,
                    to_fetch.guid_idx as guid_idx
                FROM {mirror_table}
                JOIN to_fetch
                  ON {mirror_table}.guid = to_fetch.fetch_guid

                UNION ALL

                SELECT
                    {common_cols},
                    NULL as is_overridden,
                    NULL as server_modified,
                    local_modified,
                    is_deleted,
                    sync_status,
                    0 as is_mirror,
                    to_fetch.guid_idx as guid_idx
                FROM {local_table}
                JOIN to_fetch
                  ON {local_table}.guid = to_fetch.fetch_guid",
                // giv each VALUES item 2 entries, an index and the parameter.
                vals = values_with_idx,
                local_table = schema::LOCAL_TABLE_NAME,
                mirror_table = schema::MIRROR_TABLE_NAME,
                common_cols = schema::COMMON_COLS
            );

            let mut stmt = self.db.prepare(&query)?;

            let rows = stmt.query_and_then(chunk, |row| {
                let guid_idx_i = row.get::<_, i64>("guid_idx");
                // Hitting this means our math is wrong...
                assert_ge!(guid_idx_i, 0);

                let guid_idx = guid_idx_i as usize;
                let is_mirror: bool = row.get("is_mirror");
                if is_mirror {
                    sync_data[guid_idx].set_mirror(MirrorLogin::from_row(row)?)?;
                } else {
                    sync_data[guid_idx].set_local(LocalLogin::from_row(row)?)?;
                }
                Ok(())
            })?;
            // `rows` is an Iterator<Item = Result<()>>, so we need to collect to handle the errors.
            rows.collect::<Result<_>>()?;
            Ok(())
        })?;
        Ok(sync_data)
    }

    // It would be nice if this were a batch-ish api (e.g. takes a slice of records and finds dupes
    // for each one if they exist)... I can't think of how to write that query, though.
    fn find_dupe(&self, l: &Login) -> Result<Option<Login>> {
        let form_submit_host_port = l.form_submit_url.as_ref().and_then(|s| util::url_host_port(&s));
        let args = vec![
            &l.hostname as &ToSql,
            &l.http_realm as &ToSql,
            &l.username as &ToSql,
            &form_submit_host_port as &ToSql,
        ];
        let mut query = format!("
            SELECT {common},
            FROM {local_table}
            WHERE hostname IS ?
              AND httpRealm IS ?
              AND username IS ?",
            common = schema::COMMON_COLS,
            local_table = schema::LOCAL_TABLE_NAME,
        );
        if form_submit_host_port.is_some() {
            // Stolen from iOS
            query += " AND (formSubmitURL = '' OR (instr(formSubmitURL, ?) > 0))";
        } else {
            query += " AND formSubmitURL IS ?"
        }
        Ok(self.query_row(&query, &args, |row| Login::from_row(row))?)
    }

    pub fn get_all(&self) -> Result<Vec<Login>> {
        let mut stmt = self.db.prepare_cached(&GET_ALL_SQL)?;
        let rows = stmt.query_and_then(&[], Login::from_row)?;
        rows.collect::<Result<_>>()
    }

    pub fn get_by_id(&self, id: &str) -> Result<Option<Login>> {
        self.query_row_cached(&GET_BY_GUID_SQL, &[
            &id as &ToSql,
            &id as &ToSql,
        ], Login::from_row)
    }

    pub fn touch(&self, id: &str) -> Result<()> {
        self.ensure_local_overlay_exists(id)?;
        self.mark_mirror_overridden(id)?;
        let now_us = util::system_time_us_i64(SystemTime::now());
        let now_ms = now_us / 1000;
        // As on iOS, just using a record doesn't flip it's status to changed.
        // TODO: this might be wrong for lockbox!
        self.execute_cached_with_args("
            UPDATE loginsL
               SET timeLastUsed = ?,
                   timesUsed = timesUsed + 1,
                   local_modified = ?
               WHERE guid = ?
                 AND is_deleted = 0",
            &[&now_us as &ToSql, &now_ms as &ToSql, &id as &ToSql]
        )?;
        Ok(())
    }

    pub fn add(&self, login: Login) -> Result<()> {
        login.check_valid()?;

        let now_us = util::system_time_us_i64(SystemTime::now());
        let now_ms = now_us / 1000;

        let sql = format!("
            INSERT OR IGNORE INTO loginsL (
                hostname,
                httpRealm,
                formSubmitURL,
                usernameField,
                passwordField,
                timesUsed,
                username,
                password,
                guid,
                timeCreated,
                timeLastUsed,
                timePasswordChanged,
                local_modified,
                is_deleted,
                sync_status
            ) VALUES (
                :hostname,
                :http_realm,
                :form_submit_url,
                :username_field,
                :password_field,
                1, // timesUsed
                :username,
                :password,
                :guid,
                :time_created,
                :time_last_used,
                :time_password_changed,
                :local_modified,
                0, // isDeleted
                {new} // sync_status
            )", new = SyncStatus::New as u8);

        self.db.execute_named(&sql, &[
            ("hostname", &login.hostname as &ToSql),
            ("http_realm", &login.http_realm as &ToSql),
            ("form_submit_url", &login.form_submit_url as &ToSql),
            ("username_field", &login.username_field as &ToSql),
            ("password_field", &login.password_field as &ToSql),
            ("username", &login.username as &ToSql),
            ("password", &login.password as &ToSql),
            ("guid", &login.id as &ToSql),
            ("time_created", &now_us as &ToSql),
            ("time_last_used", &now_us as &ToSql),
            ("time_password_changed", &now_us as &ToSql),
            ("local_modified", &now_ms as &ToSql)
        ])?;
        Ok(())
    }

    pub fn update(&self, login: Login) -> Result<()> {
        login.check_valid()?;
        self.ensure_local_overlay_exists(login.guid_str())?;
        self.mark_mirror_overridden(login.guid_str())?;

        let now_us = util::system_time_us_i64(SystemTime::now());
        let now_ms = now_us / 1000;

        let sql = format!("
            UPDATE loginsL
            SET local_modified      = :now_millis,
                timeLastUsed        = :now_micros,
                // Only update timePasswordChanged if, well, the password changed.
                timePasswordChanged = (CASE
                    WHEN password = :password
                    THEN timePasswordChanged
                    ELSE :now_micros
                END),
                httpRealm           = :http_realm,
                formSubmitURL       = :form_submit_url,
                usernameField       = :username_field,
                passwordField       = :password_field,
                timesUsed           = timesUsed + 1,
                username            = :username,
                password            = :password,
                hostname            = :hostname,
                // leave New records as they are, otherwise update them to `changed`
                sync_status         = max(sync_status, {changed})
            WHERE guid = :guid",
            changed = SyncStatus::Changed as u8
        );

        self.db.execute_named(&sql, &[
            ("hostname", &login.hostname as &ToSql),
            ("username", &login.username as &ToSql),
            ("password", &login.password as &ToSql),
            ("http_realm", &login.http_realm as &ToSql),
            ("form_submit_url", &login.form_submit_url as &ToSql),
            ("username_field", &login.username_field as &ToSql),
            ("password_field", &login.password_field as &ToSql),
            ("guid", &login.id as &ToSql),
            ("now_micros", &now_us as &ToSql),
            ("now_millis", &now_ms as &ToSql),
        ])?;
        Ok(())
    }

    pub fn exists(&self, id: &str) -> Result<bool> {
        Ok(self.query_row(
            &*ID_EXISTS_SQL,
            &[&id as &ToSql, &id as &ToSql],
            |row| Ok(row.get(0))
        )?.unwrap_or(false))
    }

    /// Delete the record with the provided id. Returns true if the record
    /// existed already.
    pub fn delete(&self, id: &str) -> Result<bool> {
        let exists = self.exists(id)?;
        let now_us = util::system_time_us_i64(SystemTime::now());
        let now_ms = now_us / 1000;

        // Directly delete IDs that have not yet been synced to the server
        self.db.execute(&format!("
            DELETE FROM {local}
            WHERE guid = ?
              AND sync_status = {status_new}",
            local = schema::LOCAL_TABLE_NAME,
            status_new = SyncStatus::New as u8), &[])?;

        // For IDs that have, mark is_deleted and clear sensitive fields
        self.db.execute(&format!("
            UPDATE {local}
            SET local_modified = ?,
                sync_status = {status_changed},
                is_deleted = 1,
                password = '',
                hostname = '',
                username = ''
            WHERE guid = ?",
            local = schema::LOCAL_TABLE_NAME,
            status_changed = SyncStatus::Changed as u8),
            &[&now_ms as &ToSql])?;

        // Mark the mirror as overridden
        self.db.execute(&format!("UPDATE {mirror} SET is_overridden = 1 WHERE guid = ?",
                                 mirror = schema::MIRROR_TABLE_NAME),
                        &[&now_ms as &ToSql])?;

        // If we don't have a local record for this ID, but do have it in the mirror
        // insert a tombstone.
        self.db.execute(&format!("
            INSERT OR IGNORE INTO {local}
                    (guid, local_modified, is_deleted, sync_status, hostname, timeCreated, timePasswordChanged, password, username)
            SELECT   guid, ?,              1,          {changed},   '',       timeCreated, ?,                   '',       ''
            FROM {mirror}
            WHERE  guid = ?",
            local = schema::LOCAL_TABLE_NAME,
            mirror = schema::MIRROR_TABLE_NAME,
            changed = SyncStatus::Changed as u8),
            &[&now_ms as &ToSql, &now_us as &ToSql])?;

        Ok(exists)
    }

    fn ensure_local_overlay_exists(&self, guid: &str) -> Result<()> {
        let already_have_local: bool = self.query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM loginsL WHERE guid = ?)",
            &[&guid as &ToSql],
            |row| Ok(row.get(0))
        )?.unwrap_or_default();

        if already_have_local {
            return Ok(())
        }

        debug!("No overlay; cloning one for {:?}.", guid);
        let changed = self.clone_mirror_to_overlay(guid)?;
        if changed == 0 {
            error!("Failed to create local overlay for GUID {:?}.", guid);
            throw!(ErrorKind::NoSuchRecord(guid.to_owned()));
        }
        Ok(())
    }

    fn clone_mirror_to_overlay(&self, guid: &str) -> Result<usize> {
        self.execute_cached_with_args(&*CLONE_SINGLE_MIRROR_SQL, &[&guid as &ToSql])
    }

    pub fn reset(&self) -> Result<()> {
        info!("Executing reset on password store!");
        self.execute_all(&[
            &*CLONE_ENTIRE_MIRROR_SQL,
            "DELETE FROM loginsM",
            &format!("UPDATE loginsL SET sync_status = {}", SyncStatus::New as u8),
        ])?;
        self.set_last_sync(ServerTimestamp(0.0))?;
        // TODO: Should we clear global_state?
        Ok(())
    }

    pub fn wipe(&self) -> Result<()> {
        info!("Executing reset on password store!");
        let now_us = util::system_time_us_i64(SystemTime::now());
        let now_ms = now_us / 1000;

        self.execute(&format!("DELETE FROM loginsL WHERE sync_status = {new}", new = SyncStatus::New as u8))?;
        self.execute_with_args(
            &format!("
                UPDATE loginsL
                SET local_modified = ?,
                    sync_status = {changed},
                    is_deleted = 1,
                    password = '',
                    hostname = '',
                    username = ''
                WHERE is_deleted = 0",
                changed = SyncStatus::Changed as u8),
            &[&now_ms as &ToSql])?;

        self.execute("UPDATE loginsM SET is_overridden = 1")?;

        self.execute_with_args(
            &format!("
                INSERT OR IGNORE INTO loginsL
                      (guid, local_modified, is_deleted, sync_status, hostname, timeCreated, timePasswordChanged, password, username)
                SELECT guid, ?,              1,          {changed},   '',       timeCreated, ?,                   '',       '')
                FROM loginsM",
                changed = SyncStatus::Changed as u8),
            &[&now_ms as &ToSql, &now_us as &ToSql])?;

        Ok(())
    }

}

#[derive(Default, Debug, Clone)]
struct UpdatePlan {
    delete_mirror: Vec<String>,
    delete_local: Vec<String>,
    local_updates: Vec<MirrorLogin>,
    // the bool is the `is_overridden` flag, the i64 is ServerTimestamp in millis
    mirror_inserts: Vec<(Login, i64, bool)>,
    mirror_updates: Vec<(Login, i64)>,
}

impl UpdatePlan {
    pub fn plan_two_way_merge(&mut self, local: &Login, upstream: (Login, ServerTimestamp)) {
        let is_override = local.time_password_changed > upstream.0.time_password_changed;
        self.mirror_inserts.push((upstream.0, upstream.1.as_millis() as i64, is_override));
        if !is_override {
            self.delete_local.push(local.id.to_string());
        }
    }

    pub fn plan_three_way_merge(
        &mut self,
        local: LocalLogin,
        shared: MirrorLogin,
        upstream: Login,
        upstream_time: ServerTimestamp,
        server_now: ServerTimestamp
    ) {
        let local_age = SystemTime::now().duration_since(local.local_modified).unwrap_or_default();
        let remote_age = server_now.duration_since(upstream_time).unwrap_or_default();

        let local_delta = local.login.delta(&shared.login);
        let upstream_delta = upstream.delta(&shared.login);

        let merged_delta = local_delta.merge(upstream_delta, remote_age < local_age);

        // Update mirror to upstream
        self.mirror_updates.push((upstream, upstream_time.as_millis() as i64));
        let mut new = shared;

        new.login.apply_delta(merged_delta);
        new.server_modified = upstream_time;
        self.local_updates.push(new);
    }

    fn plan_delete(&mut self, id: String) {
        self.delete_local.push(id.to_string());
        self.delete_mirror.push(id.to_string());
    }

    fn plan_mirror_update(&mut self, login: Login, time: ServerTimestamp) {
        self.mirror_updates.push((login, time.as_millis() as i64));
    }

    fn plan_mirror_insert(&mut self, login: Login, time: ServerTimestamp, is_override: bool) {
        self.mirror_inserts.push((login, time.as_millis() as i64, is_override));
    }

    fn perform_deletes(&self, tx: &mut Transaction) -> Result<()> {
        util::each_chunk_mapped(&self.delete_local, |id| id as &ToSql, |chunk, _| {
            tx.execute(&format!("DELETE FROM {local} WHERE guid IN ({vars})",
                                local = schema::LOCAL_TABLE_NAME,
                                vars = util::sql_vars(chunk.len())),
                       chunk)?;
            Ok(())
        })?;

        util::each_chunk_mapped(&self.delete_mirror, |id| id as &ToSql, |chunk, _| {
            tx.execute(&format!("DELETE FROM {mirror} WHERE guid IN ({vars})",
                                mirror = schema::MIRROR_TABLE_NAME,
                                vars = util::sql_vars(chunk.len())),
                       chunk)?;
            Ok(())
        })?;
        Ok(())
    }

    // These aren't batched but probably should be.
    fn perform_mirror_updates(&self, tx: &mut Transaction) -> Result<()> {
        let sql = format!("
            UPDATE {mirror}
            SET server_modified = ?,
                httpRealm = ?,
                formSubmitURL = ?,
                usernameField = ?,
                timesUsed = coalesce(nullif(?, 0), timesUsed),
                timeLastUsed = coalesce(nullif(?, 0), timeLastUsed),
                timePasswordChanged = coalesce(nullif(?, 0), timePasswordChanged),
                timeCreated = coalesce(nullif(?, 0), timeCreated),
                password = ?,
                hostname = ?,
                username = ?,
            WHERE guid = ?
        ", mirror = schema::MIRROR_TABLE_NAME);
        let mut stmt = tx.prepare_cached(&sql)?;
        for (login, timestamp) in &self.mirror_updates {
            stmt.execute(&[
                timestamp as &ToSql,
                &login.http_realm as &ToSql,
                &login.form_submit_url as &ToSql,
                &login.username_field as &ToSql,
                &login.password_field as &ToSql,
                &login.times_used as &ToSql,
                &login.time_last_used as &ToSql,
                &login.time_password_changed as &ToSql,
                &login.time_created as &ToSql,
                &login.password as &ToSql,
                &login.hostname as &ToSql,
                &login.username as &ToSql,
                &login.id.as_str() as &ToSql,
            ])?;
        }
        Ok(())
    }

    fn perform_mirror_inserts(&self, tx: &mut Transaction) -> Result<()> {
        let sql = format!("
            INSERT OR IGNORE INTO {mirror} (
                is_overridden, server_modified,
                httpRealm, formSubmitURL, usernameField,
                passwordField, timesUsed, timeLastUsed, timePasswordChanged, timeCreated,
                password, hostname, username, guid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            mirror = schema::MIRROR_TABLE_NAME);
        let mut stmt = tx.prepare_cached(&sql)?;

        for (login, timestamp, is_overridden) in &self.mirror_inserts {
            stmt.execute(&[
                is_overridden as &ToSql,
                timestamp as &ToSql,
                &login.http_realm as &ToSql,
                &login.form_submit_url as &ToSql,
                &login.username_field as &ToSql,
                &login.password_field as &ToSql,
                &login.times_used as &ToSql,
                &login.time_last_used as &ToSql,
                &login.time_password_changed as &ToSql,
                &login.time_created as &ToSql,
                &login.password as &ToSql,
                &login.hostname as &ToSql,
                &login.username as &ToSql,
                &login.id.as_str() as &ToSql,
            ])?;
        }
        Ok(())
    }

    fn perform_local_updates(&self, tx: &mut Transaction) -> Result<()> {
        let sql = format!("
            UPDATE {local}
            SET local_modified = ?
                httpRealm = ?,
                formSubmitURL = ?,
                usernameField = ?,
                passwordField = ?,
                timeLastUsed = ?,
                timePasswordChanged = ?,
                timesUsed = ?,
                password = ?,
                hostname = ?,
                username = ?,
                syncStatus = {changed}
            WHERE guid = ?",
            local = schema::LOCAL_TABLE_NAME,
            changed = SyncStatus::Changed as u8);
        let mut stmt = tx.prepare_cached(&sql)?;
        // XXX OutgoingChangeset should no longer have timestamp.
        let local_ms: i64 = util::system_time_ms_i64(SystemTime::now());
        for l in &self.local_updates {
            stmt.execute(&[
                &local_ms as &ToSql,
                &l.login.http_realm as &ToSql,
                &l.login.form_submit_url as &ToSql,
                &l.login.username_field as &ToSql,
                &l.login.password_field as &ToSql,
                &l.login.time_last_used as &ToSql,
                &l.login.time_password_changed as &ToSql,
                &l.login.times_used as &ToSql,
                &l.login.password as &ToSql,
                &l.login.hostname as &ToSql,
                &l.login.username as &ToSql,
            ])?;
        }
        Ok(())
    }

    fn execute(&self, tx: &mut Transaction) -> Result<()> {
        debug!("UpdatePlan: deleting records...");
        self.perform_deletes(tx)?;
        debug!("UpdatePlan: Updating existing mirror records...");
        self.perform_mirror_updates(tx)?;
        debug!("UpdatePlan: Inserting new mirror records...");
        self.perform_mirror_inserts(tx)?;
        debug!("UpdatePlan: Updating reconciled local records...");
        self.perform_local_updates(tx)?;
        Ok(())
    }

}

impl LoginDb {

    fn reconcile(&self, records: Vec<SyncLoginData>, server_now: ServerTimestamp) -> Result<UpdatePlan> {
        let mut plan = UpdatePlan::default();

        for mut record in records {
            debug!("Processing remote change {}", record.guid());
            let upstream = if let Some(inbound) = record.inbound.0.take() {
                inbound
            } else {
                debug!("Processing inbound deletion (always prefer)");
                plan.plan_delete(record.guid.clone());
                continue;
            };
            let upstream_time = record.inbound.1;
            match (record.mirror.take(), record.local.take()) {
                (Some(mirror), Some(local)) => {
                    debug!("  Conflict between remote and local, Resolving with 3WM");
                    plan.plan_three_way_merge(
                        local, mirror, upstream, upstream_time, server_now);
                }
                (Some(_mirror), None) => {
                    debug!("  Forwarding mirror to remote");
                    plan.plan_mirror_update(upstream, upstream_time);
                }
                (None, Some(local)) => {
                    debug!("  Conflicting record without shared parent, using newer");
                    plan.plan_two_way_merge(&local.login, (upstream, upstream_time));
                }
                (None, None) => {
                    if let Some(dupe) = self.find_dupe(&upstream)? {
                        debug!("  Incoming record {} was is a dupe of local record {}", upstream.id, dupe.id);
                        plan.plan_two_way_merge(&dupe, (upstream, upstream_time));
                    } else {
                        debug!("  No dupe found, inserting into mirror");
                        plan.plan_mirror_insert(upstream, upstream_time, false);
                    }
                }
            }
        }
        Ok(plan)
    }

    fn execute_plan(&mut self, plan: UpdatePlan) -> Result<()> {
        let mut tx = self.db.transaction()?;
        plan.execute(&mut tx)?;
        tx.commit()?;
        Ok(())
    }

    fn fetch_outgoing(&mut self, st: ServerTimestamp) -> Result<OutgoingChangeset> {
        let mut outgoing = OutgoingChangeset::new("passwords".into(), st);
        let mut stmt = self.db.prepare_cached(&format!("
            SELECT * FROM {local}
            WHERE sync_status IS NOT {synced}",
            local = schema::LOCAL_TABLE_NAME,
            synced = SyncStatus::Synced as u8
        ))?;
        let rows = stmt.query_and_then(&[], |row| {
            // XXX OutgoingChangeset should no longer have timestamp.
            Ok(if row.get::<_, bool>("is_deleted") {
                Payload::new_tombstone(row.get_checked::<_, String>("guid")?)
            } else {
                Payload::from_record(Login::from_row(row)?)?
            })
        })?;
        outgoing.changes = rows.collect::<Result<_>>()?;

        Ok(outgoing)
    }

    fn do_apply_incoming(
        &mut self,
        inbound: IncomingChangeset
    ) -> Result<OutgoingChangeset> {
        let data = self.fetch_login_data(&inbound.changes)?;
        let plan = self.reconcile(data, inbound.timestamp)?;
        self.execute_plan(plan)?;
        Ok(self.fetch_outgoing(inbound.timestamp)?)
    }

    fn put_meta(&self, key: &str, value: &ToSql) -> Result<()> {
        self.execute_cached_with_args(&*META_PUT_SQL, &[&key as &ToSql, value])?;
        Ok(())
    }

    fn get_meta<T: FromSql>(&self, key: &str) -> Result<Option<T>> {
        self.query_row_cached(&*META_GET_SQL, &[&key as &ToSql], |row| Ok(row.get(0)))
    }

    pub fn set_last_sync(&self, last_sync: ServerTimestamp) -> Result<()> {
        debug!("Updating last sync to {}", last_sync);
        self.put_meta(schema::LAST_SYNC_META_KEY, &last_sync.0)
    }

    pub fn set_global_state(&self, global_state: &str) -> Result<()> {
        self.put_meta(schema::GLOBAL_STATE_META_KEY, &global_state)
    }

    pub fn get_last_sync(&self) -> Result<Option<ServerTimestamp>> {
        Ok(self.get_meta::<f64>(schema::LAST_SYNC_META_KEY)?.map(ServerTimestamp))
    }

    pub fn get_global_state(&self) -> Result<Option<String>> {
        self.get_meta::<String>(schema::GLOBAL_STATE_META_KEY)
    }
}

impl Store for LoginDb {
    type Error = Error;

    fn apply_incoming(
        &mut self,
        inbound: IncomingChangeset
    ) -> Result<OutgoingChangeset> {
        self.do_apply_incoming(inbound)
    }

    fn sync_finished(
        &mut self,
        new_timestamp: ServerTimestamp,
        records_synced: &[String],
    ) -> Result<()> {
        self.mark_as_synchronized(
            &records_synced.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            new_timestamp
        )
    }
}


lazy_static! {

    static ref ANY_SYNCED_SQL: String = format!("
        SELECT EXISTS(
            SELECT 1 from {mirror}
            UNION ALL
            SELECT 1 from {local} WHERE sync_status IS NOT {new}
        )",
        mirror = schema::MIRROR_TABLE_NAME,
        local = schema::LOCAL_TABLE_NAME,
        new = SyncStatus::New as u8
    );

    static ref META_GET_SQL: String = format!(
        "SELECT value FROM {meta_table} WHERE key = ?",
        meta_table = schema::META_TABLE_NAME
    );

    static ref META_PUT_SQL: String = format!(
        "REPLACE INTO {meta_table} (key, value) VALUES (?, ?)",
        meta_table = schema::META_TABLE_NAME
    );

    static ref GET_ALL_SQL: String = format!("
        SELECT {common_cols} FROM {local} WHERE is_deleted = 0
        UNION ALL
        SELECT {common_cols} FROM {mirror} WHERE is_overridden = 0
    ",
        common_cols = schema::COMMON_COLS,
        local = schema::LOCAL_TABLE_NAME,
        mirror = schema::MIRROR_TABLE_NAME
    );

    // Note: takes two positional args
    static ref GET_BY_GUID_SQL: String = format!("
        SELECT {common_cols}
        FROM {local}
        WHERE is_deleted = 0
          AND guid = ?

        UNION ALL

        SELECT {common_cols}
        FROM {mirror}
        WHERE is_overriden IS NOT 1
          AND guid = ?
        ORDER BY hostname ASC

        LIMIT 1
    ",
        common_cols = schema::COMMON_COLS,
        local = schema::LOCAL_TABLE_NAME,
        mirror = schema::MIRROR_TABLE_NAME
    );

    static ref ID_EXISTS_SQL: String = format!("
        SELECT EXISTS(
            SELECT 1 FROM {local}
            WHERE guid = ? AND is_deleted = 0
            UNION ALL
            SELECT 1 FROM {mirror}
            WHERE guid = ? AND is_overridden IS NOT 1
        )",
        local = schema::LOCAL_TABLE_NAME,
        mirror = schema::MIRROR_TABLE_NAME,
    );

    static ref CLONE_ENTIRE_MIRROR_SQL: String = format!("
        INSERT OR IGNORE INTO {local} ({common_cols}, local_modified, is_deleted, sync_status)
        SELECT {common_cols}, NULL AS local_modified, 0 AS is_deleted, 0 AS sync_status
        FROM {mirror}",
        local = schema::LOCAL_TABLE_NAME,
        mirror = schema::MIRROR_TABLE_NAME,
        common_cols = schema::COMMON_COLS,
    );

    static ref CLONE_SINGLE_MIRROR_SQL: String = format!(
        "{} WHERE guid = ?",
        &*CLONE_ENTIRE_MIRROR_SQL
    );

}
