/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use rusqlite::{types::ToSql, Transaction};
use std::time::SystemTime;
use error::*;
use schema;
use login::{LocalLogin, MirrorLogin, Login, SyncStatus};
use sync::ServerTimestamp;
use util;

#[derive(Default, Debug, Clone)]
pub(crate) struct UpdatePlan {
    pub delete_mirror: Vec<String>,
    pub delete_local: Vec<String>,
    pub local_updates: Vec<MirrorLogin>,
    // the bool is the `is_overridden` flag, the i64 is ServerTimestamp in millis
    pub mirror_inserts: Vec<(Login, i64, bool)>,
    pub mirror_updates: Vec<(Login, i64)>,
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

    pub fn plan_delete(&mut self, id: String) {
        self.delete_local.push(id.to_string());
        self.delete_mirror.push(id.to_string());
    }

    pub fn plan_mirror_update(&mut self, login: Login, time: ServerTimestamp) {
        self.mirror_updates.push((login, time.as_millis() as i64));
    }

    pub fn plan_mirror_insert(&mut self, login: Login, time: ServerTimestamp, is_override: bool) {
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
                passwordField = ?,
                timesUsed = coalesce(nullif(?, 0), timesUsed),
                timeLastUsed = coalesce(nullif(?, 0), timeLastUsed),
                timePasswordChanged = coalesce(nullif(?, 0), timePasswordChanged),
                timeCreated = coalesce(nullif(?, 0), timeCreated),
                password = ?,
                hostname = ?,
                username = ?
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
            SET local_modified = ?,
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
                sync_status = {changed}
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
                &l.guid_str() as &ToSql,
            ])?;
        }
        Ok(())
    }

    pub fn execute(&self, tx: &mut Transaction) -> Result<()> {
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
