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

impl LoginDb {
    pub fn with_connection(db: Connection) -> Result<Self> {
        let mut res = Self { db };
        schema::init(&mut res)?;
        Ok(res)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::with_connection(Connection::open(path)?)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Ok(Self::with_connection(Connection::open_in_memory()?)?)
    }

    pub fn vacuum(&self) -> Result<()> {
        self.execute("VACUUM")?;
        Ok(())
    }

    pub fn execute_all(&self, stmts: &[impl AsRef<str>]) -> Result<()> {
        for sql in stmts {
            self.execute(sql.as_ref())?;
        }
        Ok(())
    }

    #[inline]
    pub fn execute(&self, stmt: impl AsRef<str>) -> Result<()> {
        Ok(self.do_exec(stmt.as_ref(), &[], false)?)
    }

    #[inline]
    pub fn execute_cached(&self, stmt: impl AsRef<str>) -> Result<()> {
        Ok(self.do_exec(stmt.as_ref(), &[], true)?)
    }

    #[inline]
    pub fn execute_with_args(&self, stmt: impl AsRef<str>, params: &[&ToSql]) -> Result<()> {
        Ok(self.do_exec(stmt.as_ref(), params, false)?)
    }

    #[inline]
    pub fn execute_cached_with_args(&self, stmt: impl AsRef<str>, params: &[&ToSql]) -> Result<()> {
        Ok(self.do_exec(stmt.as_ref(), params, true)?)
    }

    fn do_exec(&self, sql: &str, params: &[&ToSql], cache: bool) -> Result<()> {
        let res = if cache {
            self.db.prepare_cached(sql)
                   .and_then(|mut s| s.execute(params))
        } else {
            self.db.execute(sql, params)
        };
        if let Err(e) = &res {
            warn!("Error running SQL {}. Statement: {:?}", e, sql);
        }
        res?;
        Ok(())
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
                    common_cols = COMMON_COLS,
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
        // XXX figure out somewhere to write ts!!!!
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
                    bail!(ErrorKind::DuplicateGuid(incoming.0.id.to_string()))
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
                common_cols = COMMON_COLS
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
            common = COMMON_COLS,
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
}

impl Store for LoginDb {

    fn apply_incoming(
        &mut self,
        inbound: IncomingChangeset
    ) -> sync::Result<OutgoingChangeset> {
        self.do_apply_incoming(inbound).map_err(|e| {
            let msg = format!("Storage error: {}", e);
            sync::Error::with_chain(e, sync::ErrorKind::UnexpectedError(msg))
        })
    }

    fn sync_finished(
        &mut self,
        new_timestamp: ServerTimestamp,
        records_synced: &[String],
    ) -> sync::Result<()> {
        self.mark_as_synchronized(
            &records_synced.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            new_timestamp
        ).map_err(|e| {
            let msg = format!("Storage error: {}", e);
            sync::Error::with_chain(e, sync::ErrorKind::UnexpectedError(msg))
        })
    }
}

static COMMON_COLS: &'static str = "
    guid, username, password,
    hostname, httpRealm, formSubmitURL,
    usernameField, passwordField,
    timeCreated, timeLastUsed,
    timePasswordChanged, timesUsed
";

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

}
