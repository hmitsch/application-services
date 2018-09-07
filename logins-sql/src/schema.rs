/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use error::*;
use db;

// Note: care is taken to be compatible with the iOS database format.
// (It's not clear if this is actually worthwhile though...)
const VERSION: i64 = 4;

pub const MIRROR_TABLE_NAME: &'static str = "loginsM";
pub const LOCAL_TABLE_NAME: &'static str = "loginsL";
pub const META_TABLE_NAME: &'static str = "loginsSyncMeta";

const IDX_MIRROR_OVERRIDEN_HOSTNAME: &'static str = "idx_loginsM_is_overridden_hostname";
const IDX_LOCAL_DELETED_HOSTNAME: &'static str = "idx_loginsL_is_deleted_hostname";

// Every column shared by both tables except for `id`
pub const COMMON_COLS: &'static str = "
    guid,
    username,
    password,
    hostname,
    httpRealm,
    formSubmitURL,
    usernameField,
    passwordField,
    timeCreated,
    timeLastUsed,
    timePasswordChanged,
    timesUsed
";

const COMMON_SQL: &'static str = "
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname            TEXT NOT NULL,
    httpRealm           TEXT,
    formSubmitURL       TEXT,
    usernameField       TEXT,
    passwordField       TEXT,
    timesUsed           INTEGER NOT NULL DEFAULT 0,
    -- Microseconds
    timeCreated         INTEGER NOT NULL,
    -- Microseconds
    timeLastUsed        INTEGER,
    -- Microseconds
    timePasswordChanged INTEGER NOT NULL,
    username            TEXT,
    password            TEXT NOT NULL,
    guid                TEXT NOT NULL UNIQUE
";



lazy_static! {
    static ref CREATE_LOCAL_TABLE_SQL: String = format!(
        "CREATE TABLE IF NOT EXISTS {local} (
            {common_sql},
            -- Milliseconds
            local_modified INTEGER,

            is_deleted     TINYINT NOT NULL DEFAULT 0,
            sync_status    TINYINT NOT NULL DEFAULT 0
        )",
        local      = LOCAL_TABLE_NAME,
        common_sql = COMMON_SQL
    );

    static ref CREATE_MIRROR_TABLE_SQL: String = format!(
        "CREATE TABLE IF NOT EXISTS {mirror} (
            {common_sql},
            server_modified INTEGER NOT NULL,
            is_overridden   TINYINT NOT NULL DEFAULT 0
        )",
        mirror     = MIRROR_TABLE_NAME,
        common_sql = COMMON_SQL
    );

    static ref CREATE_META_TABLE_SQL: String = format!(
        "CREATE TABLE IF NOT EXISTS {meta} (
            key TEXT PRIMARY KEY,
            value NOT NULL
        )",
        meta = META_TABLE_NAME,
    );

    static ref CREATE_OVERRIDE_HOSTNAME_INDEX_SQL: String = format!(
        "CREATE INDEX IF NOT EXISTS {idx_override_hostname} ON {mirror} (is_overridden, hostname)",
        idx_override_hostname = IDX_MIRROR_OVERRIDEN_HOSTNAME,
        mirror = MIRROR_TABLE_NAME
    );

    static ref CREATE_DELETED_HOSTNAME_INDEX_SQL: String = format!(
        "CREATE INDEX IF NOT EXISTS {idx_local_deleted_hostname} ON {local} (is_deleted, hostname)",
        idx_local_deleted_hostname = IDX_LOCAL_DELETED_HOSTNAME,
        local = LOCAL_TABLE_NAME
    );

    static ref SET_VERSION_SQL: String = format!(
        "PRAGMA user_version = {version}",
        version = VERSION
    );
}

pub(crate) static LAST_SYNC_META_KEY:    &'static str = "last_sync_time";
pub(crate) static GLOBAL_STATE_META_KEY: &'static str = "global_state";

pub fn init(db: &db::LoginDb) -> Result<()> {
    let user_version = db.query_one::<i64>("PRAGMA user_version")?;
    if user_version == 0 {
        let table_list_exists = db.query_one::<i64>(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'tableList'"
        )? != 0;

        if !table_list_exists {
            return create(db);
        }
    }
    if user_version != VERSION {
        if user_version < VERSION {
            upgrade(db, user_version)?;
        } else {
            warn!("Loaded future schema version {} (we only understand version {}). \
                   Optimisitically ",
                  user_version, VERSION)
        }
    }
    Ok(())
}

// https://github.com/mozilla-mobile/firefox-ios/blob/master/Storage/SQL/LoginsSchema.swift#L100
fn upgrade(db: &db::LoginDb, from: i64) -> Result<()> {
    debug!("Upgrading schema from {} to {}", from, VERSION);
    if from == VERSION {
        return Ok(());
    }
    if from == 0 {
        drop(db)?;
        create(db)?;
        return Ok(());
    }
    if from < 3 {
        // These indices were added in v3 (apparently)
        db.execute_all(&[
            &*CREATE_OVERRIDE_HOSTNAME_INDEX_SQL,
            &*CREATE_DELETED_HOSTNAME_INDEX_SQL,
        ])?;
    }
    if from < 4 {
        // The `loginsSyncMeta` table was added in v4
        db.execute_all(&[
            &*CREATE_META_TABLE_SQL,
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
        &*CREATE_META_TABLE_SQL,
        &*SET_VERSION_SQL,
    ])?;
    Ok(())
}

pub fn drop(db: &db::LoginDb) -> Result<()> {
    debug!("Dropping schema");
    db.execute_all(&[
        format!("DROP TABLE IF EXISTS {}", MIRROR_TABLE_NAME).as_str(),
        format!("DROP TABLE IF EXISTS {}", LOCAL_TABLE_NAME).as_str(),
        format!("DROP TABLE IF EXISTS {}", META_TABLE_NAME).as_str(),
        "PRAGMA user_version = 0",
    ])?;
    Ok(())
}
