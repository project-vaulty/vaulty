/*
Copyright (C) 2024  S. Ivanov

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use maplit::hashmap;

use crate::{
    app_error::{AppError, AppErrorResult, AppResult},
    config,
};

pub static mut STREAM_OUTPUT: Option<std::fs::File> = None;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Module {
    App,
    Log,
    Cfg,
    Db,
    Secrets,
    AccessKey,
    Server,
    Vault,
    Api,
    User,
}

impl Into<json::JsonValue> for Module {
    fn into(self) -> json::JsonValue {
        match &self {
            Module::App => json::JsonValue::String("app".to_owned()),
            Module::Log => json::JsonValue::String("log".to_owned()),
            Module::Cfg => json::JsonValue::String("cfg".to_owned()),
            Module::Db => json::JsonValue::String("db".to_owned()),
            Module::Secrets => json::JsonValue::String("secrets".to_owned()),
            Module::AccessKey => json::JsonValue::String("accesskey".to_owned()),
            Module::Server => json::JsonValue::String("server".to_owned()),
            Module::Vault => json::JsonValue::String("vault".to_owned()),
            Module::Api => json::JsonValue::String("api".to_owned()),
            Module::User => json::JsonValue::String("user".to_owned()),
        }
    }
}

#[macro_export]
macro_rules! log {
    ({ $($json:tt)+ }) => {
        {
            use crate::log::STREAM_OUTPUT;
            use std::io::Write;

            let stream = unsafe { STREAM_OUTPUT.as_ref() };

            let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
            let time_timestamp = now.timestamp_millis();
            let time_iso = now.to_rfc3339();

            let data = json::object!{
                t: time_timestamp,
                date: time_iso,
                $($json)+
            };

            let message = data.dump();

            if let Some(mut stream) = stream {
                let _ = write!(stream, "{message}\n");
            }

            let mut stdout = std::io::stdout();
            let _ = write!(stdout, "{message}\n");
        }
    }
}

pub fn initialize() -> AppResult<()> {
    let config = config::get_clone();

    if let Some(log_config) = config.log {
        let stream = std::fs::OpenOptions::new()
            .read(false)
            .append(true)
            .create(true)
            .open(&log_config.filename)
            .map_app_err(|e| AppError {
                message: "failed to open/create".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "filename".to_owned() => log_config.filename
                }),
            })?;

        unsafe {
            STREAM_OUTPUT = Some(stream);
        }
    }

    Ok(())
}
