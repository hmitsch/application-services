/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use sync::{Id, ServerTimestamp};
use std::time::{self, SystemTime};
use error::*;

#[derive(Debug, Clone, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub id: Id,
    pub hostname: Option<String>,

    // rename_all = "camelCase" by default will do formSubmitUrl, but we can just
    // override this one field.
    #[serde(rename = "formSubmitURL")]
    pub form_submit_url: Option<String>,

    pub http_realm: Option<String>,

    #[serde(default)]
    pub username: String,

    pub password: String,

    #[serde(default)]
    pub username_field: String,

    #[serde(default)]
    pub password_field: String,

    pub time_created: i64,
    pub time_password_changed: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_last_used: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_used: Option<i64>,
}

impl Login {
    pub fn check_valid(&self) -> Result<()> {
        if self.hostname.as_ref().map(|h| h.is_empty()).unwrap_or(true) {
            bail!(ErrorKind::InvalidLogin("Can't add a login with an empty hostname."));
        }

        if self.password.is_empty() {
            bail!(ErrorKind::InvalidLogin("Can't add a login with an empty password."));
        }

        if self.form_submit_url.is_some() && self.http_realm.is_some() {
            bail!(ErrorKind::InvalidLogin("Can't add a login with both a httpRealm and formSubmitURL."));
        }

        if self.form_submit_url.is_none() && self.http_realm.is_none() {
            bail!(ErrorKind::InvalidLogin("Can't add a login without a httpRealm or formSubmitURL."));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MirrorLogin {
    pub login: Login,
    pub is_overridden: bool,
    pub server_modified: ServerTimestamp,
}

// This doesn't really belong here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum SyncStatus {
    Synced = 0,
    Changed = 1,
    New = 2,
}

impl SyncStatus {
    #[inline]
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(SyncStatus::Synced),
            1 => Ok(SyncStatus::Changed),
            2 => Ok(SyncStatus::New),
            v => bail!(ErrorKind::BadSyncStatus(v)),
        }
    }
}


#[derive(Clone, Debug)]
pub struct LocalLogin {
    pub login: Login,
    pub sync_status: SyncStatus,
    pub is_deleted: bool,
    pub local_modified: SystemTime,
}

macro_rules! impl_login {
    ($ty:ty { $($fields:tt)* }) => {
        impl AsRef<Login> for $ty {
            #[inline]
            fn as_ref(&self) -> &Login {
                &self.login
            }
        }

        impl AsMut<Login> for $ty {
            #[inline]
            fn as_mut(&mut self) -> &mut Login {
                &mut self.login
            }
        }

        impl From<$ty> for Login {
            #[inline]
            fn from(l: $ty) -> Self {
                l.login
            }
        }

        impl From<Login> for $ty {
            #[inline]
            fn from(login: Login) -> Self {
                Self { login, $($fields)* }
            }
        }
    };
}

impl_login!(LocalLogin {
    sync_status: SyncStatus::New,
    is_deleted: false,
    local_modified: time::UNIX_EPOCH
});

impl_login!(MirrorLogin {
    is_overridden: false,
    server_modified: ServerTimestamp(0.0)
});
