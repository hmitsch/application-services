/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate serde_json;
extern crate rusqlite;
extern crate logins_sql;
extern crate sync15_adapter;
extern crate url;
extern crate reqwest;
#[macro_use] extern crate log;

pub mod error;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use error::{
    ExternError,
    with_translated_result,
    with_translated_value_result,
    with_translated_void_result,
    with_translated_string_result,
    with_translated_opt_string_result,
};

use logins_sql::{
    Login,
    PasswordEngine,
};

use std::sync::{Once, ONCE_INIT};

#[cfg(target_os = "android")]
extern {
    pub fn __android_log_write(
        level: ::std::os::raw::c_int,
        tag: *const c_char,
        text: *const c_char
    ) -> ::std::os::raw::c_int;
}

struct DevLogger;
impl log::Log for DevLogger {
    fn enabled(&self, _: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        let message = format!("{}:{} -- {}", record.level(), record.target(), record.args());
        println!("{}", message);
        #[cfg(target_os = "android")]
        {
            unsafe {
                let message = ::std::ffi::CString::new(message).unwrap();
                let level_int = match record.level() {
                    log::Level::Trace => 2,
                    log::Level::Debug => 3,
                    log::Level::Info => 4,
                    log::Level::Warn => 5,
                    log::Level::Error => 6,
                };
                let message = message.as_ptr();
                let tag = b"RustInternal\0";
                __android_log_write(level_int, tag.as_ptr() as *const c_char, message);
            }
        }
        // TODO ios (use NSLog(__CFStringMakeConstantString(b"%s\0"), ...), maybe windows? (OutputDebugStringA)
    }
    fn flush(&self) {}
}

static INIT_LOGGER: Once = ONCE_INIT;
static DEV_LOGGER: &'static log::Log = &DevLogger;

fn init_logger() {
    log::set_logger(DEV_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    std::env::set_var("RUST_BACKTRACE", "1");
    info!("Hooked up rust logger!");
}

#[inline]
unsafe fn c_str_to_str<'a>(cstr: *const c_char) -> &'a str {
    assert!(!cstr.is_null(), "Null string passed to rust function");
    CStr::from_ptr(cstr).to_str().unwrap_or_default()
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_state_new(
    mentat_db_path: *const c_char,
    encryption_key: *const c_char,
    error: *mut ExternError
) -> *mut PasswordEngine {
    INIT_LOGGER.call_once(init_logger);
    with_translated_result(error, || {
        let path = c_str_to_str(mentat_db_path);
        let key = c_str_to_str(encryption_key);
        let state = PasswordEngine::new(path, Some(key))?;
        Ok(state)
    })
}

// indirection to help `?` figure out the target error type
fn parse_url(url: &str) -> sync15_adapter::Result<url::Url> {
    Ok(url::Url::parse(url)?)
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_sync(
    state: *mut PasswordEngine,
    key_id: *const c_char,
    access_token: *const c_char,
    sync_key: *const c_char,
    tokenserver_url: *const c_char,
    error: *mut ExternError
) {
    with_translated_void_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_sync");
        let state = &mut *state;
        state.sync(
            &sync15_adapter::Sync15StorageClientInit {
                key_id: c_str_to_str(key_id).into(),
                access_token: c_str_to_str(access_token).into(),
                tokenserver_url: parse_url(c_str_to_str(tokenserver_url))?,
            },
            &sync15_adapter::KeyBundle::from_ksync_base64(
                c_str_to_str(sync_key).into()
            )?
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_touch(
    state: *const PasswordEngine,
    id: *const c_char,
    error: *mut ExternError
) {
    with_translated_void_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_touch");
        let state = &*state;
        state.touch(c_str_to_str(id))
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_delete(
    state: *const PasswordEngine,
    id: *const c_char,
    error: *mut ExternError
) -> bool {
    with_translated_value_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_delete");
        let state = &*state;
        state.delete(c_str_to_str(id))
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_wipe(
    state: *const PasswordEngine,
    error: *mut ExternError
) {
    with_translated_void_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_wipe");
        let state = &*state;
        state.wipe()
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_reset(
    state: *const PasswordEngine,
    error: *mut ExternError
) {
    with_translated_void_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_reset");
        let state = &*state;
        state.reset()
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_get_all(
    state: *const PasswordEngine,
    error: *mut ExternError
) -> *mut c_char {
    with_translated_string_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_get_all");
        let state = &*state;
        let all_passwords = state.list()?;
        let result = serde_json::to_string(&all_passwords)?;
        Ok(result)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_get_by_id(
    state: *const PasswordEngine,
    id: *const c_char,
    error: *mut ExternError
) -> *mut c_char {
    with_translated_opt_string_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_get_by_id");
        let state = &*state;
        if let Some(password) = state.get(c_str_to_str(id))? {
            Ok(Some(serde_json::to_string(&password)?))
        } else {
            Ok(None)
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_add(
    state: *const PasswordEngine,
    record_json: *const c_char,
    error: *mut ExternError
) {
    with_translated_void_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_add");
        let state = &*state;
        let parsed: Login = serde_json::from_str(c_str_to_str(record_json))?;
        state.add(parsed)
    });
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_update(
    state: *const PasswordEngine,
    record_json: *const c_char,
    error: *mut ExternError
) {
    with_translated_void_result(error, || {
        assert!(!state.is_null(), "Null state passed to sync15_passwords_update");
        let state = &*state;
        let parsed: Login = serde_json::from_str(c_str_to_str(record_json))?;
        state.update(parsed)
    });
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_destroy_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub unsafe extern "C" fn sync15_passwords_state_destroy(obj: *mut PasswordEngine) {
    if !obj.is_null() {
        drop(Box::from_raw(obj));
    }
}
