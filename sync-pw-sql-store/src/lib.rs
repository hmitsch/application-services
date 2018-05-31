/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#![recursion_limit = "1024"]

extern crate sync15_adapter as sync;

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate error_chain;

extern crate rusqlite;

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

mod login;
mod error;
mod db;
mod schema;

pub use error::{Error, ErrorKind, Result};
pub use login::Login;




