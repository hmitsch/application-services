/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

error_chain! {
    foreign_links {
        SqlError(::rusqlite::Error);
    }
    links {
        SyncError(::sync::Error, ::sync::ErrorKind);
    }

    errors {
        ParseColumnError(col: String) {
            description("Failed to parse column")
            display("Can't parse {:?} into a valid column", col)
        }
        InvalidLogin(desc: &'static str) {
            description("Invalid login")
            display("Invalid login: {}", desc)
        }
        BadSyncStatus(v: u8) {
            description("Illegal sync status in database")
            display("Illegal sync status in database: {}", v)
        }
    }
}


