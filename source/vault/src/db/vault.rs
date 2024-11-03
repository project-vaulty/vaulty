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

use super::{access, secret, DATABASE, VAULT_TABLE};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultDocument {
    pub created: String,
    pub secrets_count: i64,
    pub access_keys_count: i64,
}

pub enum UpdateVault {
    IncreaseSecrets,
    IncreaseAccessKey,
    DecreaseSecrets,
    DecreaseAccessKey,
}

pub fn update(vault: &str, update: UpdateVault, txn: &redb::WriteTransaction) -> AppResult<()> {
    let document = {
        let table = txn.open_table(VAULT_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned(),
            }),
        })?;

        /* borrow checker */
        let query = table.get(vault).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned(),
                "document".to_owned() => "VaultDocument".to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let mut document: VaultDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "document".to_owned() => "VaultDocument".to_owned()
                }),
            })?;

            match update {
                UpdateVault::IncreaseSecrets => document.secrets_count += 1,
                UpdateVault::IncreaseAccessKey => document.access_keys_count += 1,
                UpdateVault::DecreaseSecrets => document.secrets_count -= 1,
                UpdateVault::DecreaseAccessKey => document.access_keys_count -= 1,
            }

            document
        } else {
            let now: chrono::DateTime<chrono::Local> = chrono::Local::now();

            VaultDocument {
                created: now.to_rfc3339(),
                secrets_count: if matches!(update, UpdateVault::IncreaseSecrets) {
                    1
                } else {
                    0
                },
                access_keys_count: if matches!(update, UpdateVault::IncreaseAccessKey) {
                    1
                } else {
                    0
                },
            }
        }
    };

    {
        let mut table = txn.open_table(VAULT_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned(),
            }),
        })?;

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "VaultDocument".to_owned()
            }),
        })?;

        let _ = table
            .insert(vault, document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to insert/update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => VAULT_TABLE.name().to_owned(),
                    "document".to_owned() => "VaultDocument".to_owned()
                }),
            })?;
    }

    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ListVaultDocument {
    pub vault: String,
    pub created: String,
    pub secrets_count: i64,
    pub access_keys_count: i64,
}

pub fn list() -> AppResult<Vec<ListVaultDocument>> {
    let mut result = Vec::new();
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(VAULT_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => VAULT_TABLE.name().to_owned()
        }),
    })?;

    let mut table_iter = table.iter().map_app_err(|e| AppError {
        message: "failed to iter over table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => VAULT_TABLE.name().to_owned()
        }),
    })?;

    while let Some(entry) = table_iter.next() {
        let (key, value) = entry.map_app_err(|e| AppError {
            message: "failed to iter next value".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned()
            }),
        })?;

        let vault = key.value().to_string();
        let mut value = value.value().to_owned();

        let value: VaultDocument =
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => VAULT_TABLE.name().to_owned(),
                    "document".to_owned() => "VaultDocument".to_owned()
                }),
            })?;

        result.push(ListVaultDocument {
            vault,
            created: value.created,
            secrets_count: value.secrets_count,
            access_keys_count: value.access_keys_count,
        });
    }

    Ok(result)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindVaultDocument {
    pub vault: String,
    pub created: String,
    pub secrets_count: i64,
    pub access_keys_count: i64,
}

pub fn find(vault: &str) -> AppResult<Option<FindVaultDocument>> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(VAULT_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => VAULT_TABLE.name().to_owned()
        }),
    })?;

    if let Some(value) = table.get(vault).map_app_err(|e| AppError {
        message: "failed to retrive a document".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => VAULT_TABLE.name().to_owned()
        }),
    })? {
        let mut value = value.value().to_owned();
        let document: VaultDocument =
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => VAULT_TABLE.name().to_owned(),
                    "document".to_owned() => "VaultDocument".to_owned()
                }),
            })?;

        Ok(Some(FindVaultDocument {
            vault: vault.to_string(),
            created: document.created,
            secrets_count: document.secrets_count,
            access_keys_count: document.access_keys_count,
        }))
    } else {
        Ok(None)
    }
}

pub enum DeleteVaultResult {
    Deleted,
    NotFound,
}

pub fn delete(vault: &str) -> AppResult<DeleteVaultResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table_found = {
        let table = txn.open_table(VAULT_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned()
            }),
        })?;

        let result = table.get(vault).map_app_err(|e| AppError {
            message: "failed to retrive a document".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned()
            }),
        })?;

        result.is_some()
    };

    let result = if table_found {
        let mut table = txn.open_table(VAULT_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned()
            }),
        })?;

        table.remove(vault).map_app_err(|e| AppError {
            message: "failed to delete a key".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => VAULT_TABLE.name().to_owned()
            }),
        })?;

        access::purge(vault, &txn)?;
        secret::purge(vault, &txn)?;

        DeleteVaultResult::Deleted
    } else {
        DeleteVaultResult::NotFound
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: None,
    })?;

    Ok(result)
}
