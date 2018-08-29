/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use error::*;
use rusqlite::{types::{self, ToSql}, Row};
use std::{fmt, time};
use db::MAX_VARIABLE_NUMBER;
use url::Url;

pub fn each_chunk_mapped<'a, T: 'a>(
    items: &'a [T],
    to_sql: impl Fn(&'a T) -> &'a ToSql,
    mut do_chunk: impl FnMut(&[&ToSql], usize) -> Result<()>
) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let sql_null = types::Value::Null;
    let mut arr = [&sql_null as &ToSql; MAX_VARIABLE_NUMBER];
    let mut offset = 0;
    for chunk in items.chunks(MAX_VARIABLE_NUMBER) {
        let mut slice = &mut arr[..chunk.len()];
        for (j, c) in chunk.iter().enumerate() {
            slice[j] = to_sql(c);
        }
        do_chunk(slice, offset)?;
        offset += chunk.len();
    }
    Ok(())
}

pub fn each_chunk<'a, T: ToSql + 'a>(
    items: &[T],
    do_chunk: impl FnMut(&[&ToSql], usize) -> Result<()>
) -> Result<()> {
    each_chunk_mapped(items, |t| t as &ToSql, do_chunk)
}

#[derive(Debug, Clone)]
pub struct RepeatDisplay<'a, F> {
    count: usize,
    sep: &'a str,
    fmt_one: F
}

impl<'a, F> fmt::Display for RepeatDisplay<'a, F>
where F: Fn(usize, &mut fmt::Formatter) -> fmt::Result {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.count {
            if i != 0 {
                f.write_str(self.sep)?;
            }
            (self.fmt_one)(i, f)?;
        }
        Ok(())
    }
}

pub fn repeat_display<'a, F>(count: usize, sep: &'a str, fmt_one: F) -> RepeatDisplay<'a, F>
where F: Fn(usize, &mut fmt::Formatter) -> fmt::Result {
    RepeatDisplay { count, sep, fmt_one }
}

pub fn sql_vars(count: usize) -> impl fmt::Display {
    repeat_display(count, ",", |_, f| write!(f, "?"))
}

pub fn sql_values(count: usize) -> impl fmt::Display {
    repeat_display(count, ",", |_, f| write!(f, "(?)"))
}

pub fn url_host_port(url_str: &str) -> Option<String> {
    let url = Url::parse(url_str).ok()?;
    let host = url.host_str()?;
    Some(if let Some(p) = url.port() {
        format!("{}:{}", host, p)
    } else {
        host.to_string()
    })
}

pub fn system_time_from_row(row: &Row, col_name: &str) -> Result<time::SystemTime> {
    let time_ms = row.get_checked::<_, i64>(col_name)? as u64;
    Ok(time::UNIX_EPOCH + time::Duration::from_millis(time_ms))
}

pub fn duration_ms_i64(d: time::Duration) -> i64 {
    (d.as_secs() as i64) * 1000 + ((d.subsec_nanos() as i64) * 1_000_000)
}

pub fn system_time_ms_i64(t: time::SystemTime) -> i64 {
    duration_ms_i64(t.duration_since(time::UNIX_EPOCH).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vars() {
        assert_eq!(format!("{}", sql_vars(1)), "?");
        assert_eq!(format!("{}", sql_vars(2)), "?,?");
        assert_eq!(format!("{}", sql_vars(3)), "?,?,?");
    }

    #[test]
    fn test_vals() {
        assert_eq!(format!("{}", sql_values(1)), "(?)");
        assert_eq!(format!("{}", sql_values(2)), "(?),(?)");
        assert_eq!(format!("{}", sql_values(3)), "(?),(?),(?)");
    }

    #[test]
    fn test_repeat_disp() {
        assert_eq!(format!("{}", repeat_display(1, ",", |i, f| write!(f, "({},?)", i))),
                   "(0,?)");
        assert_eq!(format!("{}", repeat_display(2, ",", |i, f| write!(f, "({},?)", i))),
                   "(0,?),(1,?)");
        assert_eq!(format!("{}", repeat_display(3, ",", |i, f| write!(f, "({},?)", i))),
                   "(0,?),(1,?),(2,?)");
    }
}

