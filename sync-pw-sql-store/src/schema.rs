/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use error::*;
use db;

const VERSION: i64 = 3;

pub static MIRROR_TABLE_NAME: &'static str = "loginsM";
pub static LOCAL_TABLE_NAME: &'static str = "loginsL";

static IDX_OVERRIDE_HOSTNAME: &'static str = "idx_loginsM_is_overridden_hostname";
static IDX_DELETED_HOSTNAME: &'static str = "idx_loginsL_is_deleted_hostname";

static COMMON_SQL: &'static str = "
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname            TEXT NOT NULL,
    httpRealm           TEXT,
    formSubmitURL       TEXT,
    usernameField       TEXT,
    passwordField       TEXT,
    timesUsed           INTEGER NOT NULL DEFAULT 0,
    timeCreated         INTEGER NOT NULL,
    timeLastUsed        INTEGER,
    timePasswordChanged INTEGER NOT NULL,
    username            TEXT,
    password            TEXT NOT NULL,
    guid                TEXT NOT NULL UNIQUE
";

lazy_static! {
    pub static ref CREATE_LOCAL_TABLE_SQL: String = format!(
        "CREATE TABLE IF NOT EXISTS {} (
            {},
            local_modified INTEGER,
            is_deleted     TINYINT NOT NULL DEFAULT 0,
            sync_status    TINYINT NOT NULL DEFAULT 0
        )",
        LOCAL_TABLE_NAME,
        COMMON_SQL
    );

    pub static ref CREATE_MIRROR_TABLE_SQL: String = format!(
        "CREATE TABLE IF NOT EXISTS {} (
            {},
            server_modified INTEGER NOT NULL,
            is_overridden   TINYINT NOT NULL DEFAULT 0
        )",
        MIRROR_TABLE_NAME,
        COMMON_SQL
    );


    pub static ref CREATE_OVERRIDE_HOSTNAME_INDEX_SQL: String = format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (is_overridden, hostname)",
        IDX_OVERRIDE_HOSTNAME,
        MIRROR_TABLE_NAME
    );

    pub static ref CREATE_DELETED_HOSTNAME_INDEX_SQL: String = format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (is_deleted, hostname)",
        IDX_DELETED_HOSTNAME,
        MIRROR_TABLE_NAME
    );
    pub static ref SET_VERSION_SQL: String = format!(
        "PRAGMA user_version = {}",
        VERSION
    );
}

pub fn init(db: &db::LoginDb) -> Result<()> {
    let user_version = db.query_one::<i64>("PRAGMA user_version")?;
    if user_version == 0 {
        let table_list_exists = db.query_returns_results(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tableList'"
        )?;

        if !table_list_exists {
            return create(db);
        }
    }
    if user_version != VERSION {
        upgrade(db, user_version)?;
    }
    Ok(())
}

// https://github.com/mozilla-mobile/firefox-ios/blob/master/Storage/SQL/LoginsSchema.swift#L100
fn upgrade(db: &db::LoginDb, from: i64) -> Result<()> {
    let to = VERSION;
    debug!("Upgrading schema from {} to {}", from, to);
    if from == to {
        return Ok(());
    }
    if from == 0 {
        drop(db)?;
        create(db)?;
        return Ok(());
    }
    if from < 3 && to >= 3 {
        // Added in version 3 apparently?
        db.execute_all(&[
            &*CREATE_OVERRIDE_HOSTNAME_INDEX_SQL,
            &*CREATE_DELETED_HOSTNAME_INDEX_SQL,
            &*SET_VERSION_SQL,
        ])?;
    }
    Ok(())
}

pub fn create(db: &db::LoginDb) -> Result<()> {
    debug!("Creating schema");
    db.execute_all(&[
        &*CREATE_LOCAL_TABLE_SQL,
        &*CREATE_MIRROR_TABLE_SQL,
        &*CREATE_OVERRIDE_HOSTNAME_INDEX_SQL,
        &*CREATE_DELETED_HOSTNAME_INDEX_SQL,
        &*SET_VERSION_SQL,
    ])?;
    Ok(())
}

pub fn drop(db: &db::LoginDb) -> Result<()> {
    debug!("Dropping schema");
    db.execute_all(&[
        format!("DROP TABLE IF EXISTS {}", MIRROR_TABLE_NAME).as_str(),
        format!("DROP TABLE IF EXISTS {}", LOCAL_TABLE_NAME).as_str(),
        "PRAGMA user_version = 0",
    ])?;
    Ok(())
}
