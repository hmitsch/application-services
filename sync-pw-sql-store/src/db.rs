/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use rusqlite::{Connection, types::{ToSql, FromSql}, Row};
use std::{time, path::Path};
use error::*;
use schema;
use login::{LocalLogin, MirrorLogin, Login, SyncStatus};
use sync::{Id, ServerTimestamp};

pub const MAX_VARIABLE_NUMBER: usize = 999;

pub struct LoginDb {
    db: Connection,
}

impl LoginDb {
    pub fn with_connection(mut db: Connection) -> Result<Self> {
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
    pub fn query_returns_results(&self, sql: &str) -> Result<bool> {
        Ok(self.query_one::<i64>(&format!("SELECT EXISTS({})", sql))? == 1)
    }
}

lazy_static! {
    static ref VARIABLES: String = ["?"; MAX_VARIABLE_NUMBER].join(",");
}

fn get_variables(n: usize) -> &'static str {
    assert!(n < MAX_VARIABLE_NUMBER);
    assert_ne!(n, 0);
    &(*VARIABLES)[..(n * 2 - 1)]
}



// login specific stuff.

impl LoginDb {

    pub fn have_synced_logins(&self) -> Result<bool> {
        let sql = format!(
            "SELECT 1 from {mirror}
             UNION ALL
             SELECT 1 from {local} WHERE sync_status IS NOT {new}",
            mirror = schema::MIRROR_TABLE_NAME,
            local = schema::LOCAL_TABLE_NAME,
            new = SyncStatus::New as u8
        );
        Ok(self.query_returns_results(&sql)?)
    }

    fn mark_as_synchronized(&mut self, guids: &[&str], ts: ServerTimestamp) -> Result<()> {
        if guids.len() == 0 {
            return Ok(());
        }

        let mut v: Vec<&ToSql> = Vec::new();
        let tx = self.db.transaction()?;

        for chunk in guids.chunks(MAX_VARIABLE_NUMBER) {
            v.clear();
            v.extend(chunk.iter().map(|s| s as &ToSql));

            let vars = get_variables(chunk.len());
            tx.execute(
                &format!("DELETE FROM {mirror_table} WHERE guid IN ({vars})",
                         mirror_table = schema::MIRROR_TABLE_NAME,
                         vars = vars),
                &v
            )?;

            tx.execute(
                &format!("
                    INSERT OR IGNORE INTO {mirror_table} (
                        is_overridden, server_modified,
                        httpRealm, formSubmitURL, usernameField,
                        passwordField, timesUsed, timeLastUsed, timePasswordChanged, timeCreated,
                        password, hostname, username, guid
                    )
                    SELECT
                        0, {modified_ms_i64},
                        httpRealm, formSubmitURL, usernameField,
                        passwordField, timesUsed, timeLastUsed, timePasswordChanged, timeCreated,
                        password, hostname, username, guid
                    FROM {local_table}
                    WHERE guid in ({vars})",
                    mirror_table = schema::MIRROR_TABLE_NAME,
                    local_table = schema::LOCAL_TABLE_NAME,
                    modified_ms_i64 = ts.as_millis() as i64,
                    vars = vars
                ),
                &v
            )?;

            tx.execute(
                &format!("DELETE FROM {local_table} WHERE guid IN ({vars})",
                         local_table = schema::MIRROR_TABLE_NAME,
                         vars = vars),
                &v
            )?;
        }

        tx.commit()?;

        Ok(())
    }

    fn get_local_login(&self, guid: &Id) -> Result<Option<LocalLogin>> {
        self.query_row_cached(
            &format!("
                SELECT
                    username, password,
                    hostname, httpRealm, formSubmitURL,
                    usernameField, passwordField,
                    timeCreated, timeLastUsed,
                    timePasswordChanged, timesUsed,
                    local_modified, is_deleted, sync_status
                FROM {local}
                WHERE guid = ?",
                local = schema::LOCAL_TABLE_NAME),
            &[&guid.as_str() as &ToSql],
            |row| {
                Ok(LocalLogin {
                    login: Login {
                        id: guid.clone(),
                        // Sadly, rusqlite doesn't allow you to get an entry from the row by name.
                        username: row.get::<_, Option<String>>(0).unwrap_or_default(),
                        password: row.get(1),

                        hostname: row.get(2),
                        http_realm: row.get(3),
                        form_submit_url: row.get(4),

                        username_field: row.get(5),
                        password_field: row.get(6),

                        time_created: row.get(7),
                        time_last_used: row.get(8),

                        time_password_changed: row.get(9),
                        times_used: row.get(10),
                    },
                    // XXX should probably be more careful about garbage data in local_modified here...
                    local_modified: time::UNIX_EPOCH + time::Duration::from_millis(row.get::<_, i64>(11) as u64),
                    is_deleted: row.get(12),
                    sync_status: SyncStatus::from_u8(row.get::<_, u8>(13))?
                })
            }
        )
    }

    fn get_mirror_login(&self, guid: &Id) -> Result<Option<MirrorLogin>> {
        self.query_row_cached(
            &format!("
                SELECT
                    username, password,
                    hostname, httpRealm, formSubmitURL,
                    usernameField, passwordField,
                    timeCreated, timeLastUsed,
                    timePasswordChanged, timesUsed,
                    is_overridden, server_modified
                FROM {mirror}
                WHERE guid = ?",
                mirror = schema::MIRROR_TABLE_NAME),
            &[&guid.as_str() as &ToSql],
            |row| {
                Ok(MirrorLogin {
                    login: Login {
                        // Sadly, rusqlite doesn't allow you to get an entry from the row by name.
                        id: guid.clone(),
                        username: row.get::<_, Option<String>>(0).unwrap_or_default(),
                        password: row.get(1),

                        hostname: row.get(2),
                        http_realm: row.get(3),
                        form_submit_url: row.get(4),

                        username_field: row.get(5),
                        password_field: row.get(6),

                        time_created: row.get(7),
                        time_last_used: row.get(8),

                        time_password_changed: row.get(9),
                        times_used: row.get(10),
                    },
                    is_overridden: row.get(11),
                    server_modified: ServerTimestamp((row.get::<_, i64>(12) as f64) / 1000.0)
                })
            }
        )
    }

    fn get_logins_with_guid(&self, guid: &Id) -> Result<(Option<LocalLogin>, Option<MirrorLogin>)> {
        let local = self.get_local_login(guid)?;
        let mirror = self.get_mirror_login(guid)?;
        Ok((local, mirror))
    }



    // fn apply_incoming(
    //     &mut self,
    //     inbound: IncomingChangeset
    // ) -> Result<OutgoingChangeset>;

    // fn sync_finished(
    //     &mut self,
    //     new_timestamp: ServerTimestamp,
    //     records_synced: &[Id],
    // ) -> Result<()>;
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vars() {
        assert_eq!(get_variables(1), "?");
        assert_eq!(get_variables(2), "?,?");
        assert_eq!(get_variables(3), "?,?,?");
        assert!(get_variables(MAX_VARIABLE_NUMBER).ends_with("?"));
    }
}
