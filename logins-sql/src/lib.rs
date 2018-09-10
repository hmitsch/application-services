/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate sync15_adapter as sync;

#[macro_use]
extern crate log;

#[cfg(test)]
extern crate env_logger;

#[macro_use]
extern crate lazy_static;

extern crate failure;

#[macro_use]
extern crate failure_derive;

#[macro_use]
extern crate more_asserts;

extern crate url;

extern crate rusqlite;

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod error;
mod login;

pub mod schema;
pub mod util;
pub mod db;
pub mod engine;
mod update_plan;

pub use error::*;
pub use login::*;
pub use engine::*;



