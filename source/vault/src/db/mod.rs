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

pub mod access;
pub mod secret;
pub mod user;
pub mod vault;

static mut DATABASE: once_cell::sync::Lazy<Option<redb::Database>> =
    once_cell::sync::Lazy::new(|| None);

const ACCESS_KEY_TABLE: redb::TableDefinition<(&str, &str), &str> =
    redb::TableDefinition::new("access-key");
const SECRETS_TABLE: redb::TableDefinition<(&str, &str), &str> =
    redb::TableDefinition::new("secrets");
const USERS_TABLE: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("users");
const VAULT_TABLE: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("vault");

pub enum InitializeState {
    Ok,
    Created,
}

#[cfg(debug_assertions)]
fn populate_db(filename: &str) -> anyhow::Result<()> {
    use crate::app_error::AppErrorToAnyhowResult;

    let content = std::fs::read_to_string(filename)?;
    let content: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if let Some(object) = content.as_mapping() {
        for (key, value) in object {
            let key = key.as_str().unwrap();

            match key {
                "insert_access_key" => {
                    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
                    struct InsertAccessKey {
                        vault: String,
                        access_key: String,
                        document: access::AccessKeyDocument,
                    }

                    let value: InsertAccessKey = serde_yaml::from_value(value.clone())?;

                    access::insert(&value.vault, &value.access_key, value.document)
                        .to_anyhow_error()?;
                }
                "insert_secret" => {
                    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
                    struct InsertSecret {
                        vault: String,
                        secret_name: String,
                        document: secret::SecretDocument,
                    }

                    let value: InsertSecret = serde_yaml::from_value(value.clone())?;

                    secret::insert(&value.vault, &value.secret_name, value.document)
                        .to_anyhow_error()?;
                }
                "insert_user" => {
                    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
                    struct InsertUser {
                        username: String,
                        document: user::UserDocument,
                    }

                    let value: InsertUser = serde_yaml::from_value(value.clone())?;

                    user::insert(&value.username, value.document).to_anyhow_error()?;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

pub fn initialize() -> AppResult<InitializeState> {
    let config_clone = config::get_clone();
    let database_path = std::path::Path::new(&config_clone.db.location);

    if database_path.exists() {
        let database = redb::Database::open(database_path).map_app_err(|e| {
            let datbase_path = database_path.to_str().unwrap_or("N/A").to_owned();

            AppError {
                message: "failed to open".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "filename".to_owned() => datbase_path
                }),
            }
        })?;

        unsafe {
            *DATABASE = Some(database);
        }

        Ok(InitializeState::Ok)
    } else {
        let database = redb::Database::create(database_path).map_app_err(|e| {
            let datbase_path = database_path.to_str().unwrap_or("N/A").to_owned();

            AppError {
                message: "failed to create".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "filename".to_owned() => datbase_path
                }),
            }
        })?;

        unsafe {
            *DATABASE = Some(database);
        }

        #[cfg(debug_assertions)]
        if let Some(filename) = config_clone.db.debug_populate {
            populate_db(&filename).map_app_err(|e| AppError {
                message: "debug populate failed".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "filename".to_owned() => filename
                }),
            })?;
        }

        Ok(InitializeState::Created)
    }
}
