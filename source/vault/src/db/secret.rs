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
use redb::{ReadableTable, TableHandle};

use crate::app_error::{AppError, AppErrorResult, AppResult};

use super::{vault, DATABASE, SECRETS_TABLE};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretDocument {
    pub created: String,
    pub secret: String,
}

pub enum InsertSecretResult {
    Inserted,
    Updated,
}

pub fn insert(
    vault: &str,
    secret_name: &str,
    document: SecretDocument,
) -> AppResult<InsertSecretResult> {
    let document = simd_json::to_string(&document).map_app_err(|e| AppError {
        message: "failed to serialize document to JSON".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "document".to_owned() => "SecretDocument".to_owned()
        }),
    })?;

    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let result = {
        let mut table = txn.open_table(SECRETS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => SECRETS_TABLE.name().to_owned()
            }),
        })?;

        if table
            .insert((vault, secret_name), document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to insert a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => SECRETS_TABLE.name().to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "secret_name".to_owned() => secret_name.to_owned()
                }),
            })?
            .is_some()
        {
            InsertSecretResult::Updated
        } else {
            InsertSecretResult::Inserted
        }
    };

    if matches!(result, InsertSecretResult::Inserted) {
        vault::update(vault, vault::UpdateVault::IncreaseSecrets, &txn)?;
    }

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => SECRETS_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "secret_name".to_owned() => secret_name.to_owned()
        }),
    })?;

    Ok(result)
}

pub enum DeleteSecretResult {
    Deleted,
    NotFound,
}

pub fn delete(vault: &str, secret_name: &str) -> AppResult<DeleteSecretResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let result = {
        let mut table = txn.open_table(SECRETS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => SECRETS_TABLE.name().to_owned()
            }),
        })?;

        if table
            .remove((vault, secret_name))
            .map_app_err(|e| AppError {
                message: "failed to delete a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => SECRETS_TABLE.name().to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "secret_name".to_owned() => secret_name.to_owned()
                }),
            })?
            .is_some()
        {
            DeleteSecretResult::Deleted
        } else {
            DeleteSecretResult::NotFound
        }
    };

    if matches!(result, DeleteSecretResult::Deleted) {
        vault::update(vault, vault::UpdateVault::DecreaseSecrets, &txn)?;
    }

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => SECRETS_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "secret_name".to_owned() => secret_name.to_owned()
        }),
    })?;

    Ok(result)
}

pub fn find(vault: &str, secret_name: &str) -> AppResult<Option<SecretDocument>> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(SECRETS_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => SECRETS_TABLE.name().to_owned()
        }),
    })?;

    if let Some(value) = table.get((vault, secret_name)).map_app_err(|e| AppError {
        message: "failed to retrive a document".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => SECRETS_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "secret_name".to_owned() => secret_name.to_owned()
        }),
    })? {
        let mut value = value.value().to_owned();

        Ok(
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => SECRETS_TABLE.name().to_owned(),
                    "document".to_owned() => "SecretDocument".to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "secret_name".to_owned() => secret_name.to_owned()
                }),
            })?,
        )
    } else {
        Ok(None)
    }
}

pub struct SecretListEntry {
    pub created: String,
    pub secret_name: String,
}

pub fn list(vault: &str) -> AppResult<Vec<SecretListEntry>> {
    let mut result = Vec::new();
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(SECRETS_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => SECRETS_TABLE.name().to_owned()
        }),
    })?;

    let mut table_iter = table.iter().map_app_err(|e| AppError {
        message: "failed to iter over table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => SECRETS_TABLE.name().to_owned()
        }),
    })?;

    while let Some(entry) = table_iter.next() {
        let (key, value) = entry.map_app_err(|e| AppError {
            message: "failed to iter next value".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => SECRETS_TABLE.name().to_owned(),
                "vault".to_owned() => vault.to_owned(),
            }),
        })?;

        let mut value = value.value().to_string();

        let document: SecretDocument =
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => SECRETS_TABLE.name().to_owned(),
                    "document".to_owned() => "SecretDocument".to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                }),
            })?;

        let (secret_ns, secret_name) = key.value();

        if secret_ns == vault {
            result.push(SecretListEntry {
                created: document.created,
                secret_name: secret_name.to_owned(),
            });
        }
    }

    Ok(result)
}

pub fn purge(vault: &str, txn: &redb::WriteTransaction) -> AppResult<()> {
    let mut to_delete = Vec::new();

    {
        let table = txn.open_table(SECRETS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => SECRETS_TABLE.name().to_owned()
            }),
        })?;

        let mut table_iter = table.iter().map_app_err(|e| AppError {
            message: "failed to iter over table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => SECRETS_TABLE.name().to_owned()
            }),
        })?;

        while let Some(entry) = table_iter.next() {
            let (key, _) = entry.map_app_err(|e| AppError {
                message: "failed to iter next value".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => SECRETS_TABLE.name().to_owned()
                }),
            })?;

            let (access_key_ns, access_key) = key.value();

            if access_key_ns == vault {
                to_delete.push((access_key_ns.to_string(), access_key.to_string()));
            }
        }
    }

    if !to_delete.is_empty() {
        let mut table = txn.open_table(SECRETS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => SECRETS_TABLE.name().to_owned()
            }),
        })?;

        for key in to_delete {
            table
                .remove((key.0.as_str(), key.1.as_str()))
                .map_app_err(|e| AppError {
                    message: "failed to delete a key".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "table".to_owned() => SECRETS_TABLE.name().to_owned(),
                        "vault".to_owned() => vault.to_owned(),
                    }),
                })?;
        }
    }

    Ok(())
}
