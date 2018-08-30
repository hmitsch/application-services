/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use login::Login;
use error::*;
use sync::{self, Sync15StorageClient, Sync15StorageClientInit, GlobalState, KeyBundle};
use db::LoginDb;
use std::path::Path;
use serde_json;

#[derive(Debug)]
pub struct SyncInfo {
    pub state: GlobalState,
    pub client: Sync15StorageClient,
    // Used so that we know whether or not we need to re-initialize `client`
    pub last_client_init: Sync15StorageClientInit,
}

// This isn't really an engine in the firefox sync15 desktop sense -- it's
// really a bundle of state that contains the sync storage client, the sync
// state, and the login DB.
pub struct PasswordEngine {
    pub sync: Option<SyncInfo>,
    pub db: LoginDb,
}

impl PasswordEngine {

    pub fn new(path: impl AsRef<Path>, encryption_key: Option<&str>) -> Result<Self> {
        let db = LoginDb::open(path, encryption_key)?;
        Ok(Self { db, sync: None })
    }

    pub fn new_in_memory(encryption_key: Option<&str>) -> Result<Self> {
        let db = LoginDb::open_in_memory(encryption_key)?;
        Ok(Self { db, sync: None })
    }

    pub fn list(&self) -> Result<Vec<Login>> {
        self.db.get_all()
    }

    pub fn get(&self, id: &str) -> Result<Option<Login>> {
        self.db.get_by_id(id)
    }

    pub fn touch(&self, id: &str) -> Result<()> {
        self.db.touch(id)
    }

    pub fn delete(&self, id: &str) -> Result<bool> {
        self.db.delete(id)
    }

    // TODO: wipe, reset, add, update

    pub fn sync(
        &mut self,
        storage_init: &Sync15StorageClientInit,
        root_sync_key: &KeyBundle
    ) -> Result<()> {

        // Note: If `to_ready` (or anything else with a ?) fails below, this
        // `take()` means we end up with `state.sync.is_none()`, which means the
        // next sync will redownload meta/global, crypto/keys, etc. without
        // needing to. Apparently this is both okay and by design.
        let maybe_sync_info = self.sync.take().map(Ok);

        let mut sync_info = maybe_sync_info.unwrap_or_else(|| -> Result<SyncInfo> {
            info!("First time through since unlock. Trying to load persisted global state.");
            let state = if let Some(persisted_global_state) = self.db.get_global_state()? {
                serde_json::from_str::<GlobalState>(&persisted_global_state)
                .unwrap_or_else(|_| {
                    // Don't log the error since it might contain sensitive
                    // info like keys (the JSON does, after all).
                    error!("Failed to parse GlobalState from JSON! Falling back to default");
                    // Unstick ourselves by using the default state.
                    GlobalState::default()
                })
            } else {
                info!("No previously persisted global state, using default");
                GlobalState::default()
            };
            let client = Sync15StorageClient::new(storage_init.clone())?;
            Ok(SyncInfo {
                state,
                client,
                last_client_init: storage_init.clone(),
            })
        })?;

        // If the options passed for initialization of the storage client aren't
        // the same as the ones we used last time, reinitialize it. (Note that
        // we could avoid the comparison in the case where we had `None` in
        // `state.sync` before, but this probably doesn't matter).
        if storage_init != &sync_info.last_client_init {
            info!("Detected change in storage client init, updating");
            sync_info.client = Sync15StorageClient::new(storage_init.clone())?;
            sync_info.last_client_init = storage_init.clone();
        }

        {
            // Scope borrow of `sync_info.client`
            let mut state_machine =
                sync::SetupStateMachine::for_full_sync(&sync_info.client, &root_sync_key);
            info!("Advancing state machine to ready (full)");
            let next_sync_state = state_machine.to_ready(sync_info.state)?;
            sync_info.state = next_sync_state;
        }

        info!("Updating persisted global state");
        let s = sync_info.state.to_persistable_string();
        self.db.set_global_state(&s)?;

        info!("Syncing passwords engine!");

        let ts = self.db.get_last_sync()?.unwrap_or_default();
        sync::synchronize(
            &sync_info.client,
            &sync_info.state,
            &mut self.db,
            "passwords".into(),
            ts,
            true
        )?;
        info!("Sync was successful!");
        self.sync = Some(sync_info);
        Ok(())
    }

}

