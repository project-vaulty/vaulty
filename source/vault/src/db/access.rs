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

use crate::{
    app_error::{AppError, AppErrorResult, AppResult},
    permission,
};

use super::{vault, ACCESS_KEY_TABLE, DATABASE};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessKeySgDocument {
    pub network: String,
    pub prefix: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessKeyDocument {
    pub secret_access_key: String,
    pub permission: Vec<permission::VaultRoles>,
    pub sg: Vec<AccessKeySgDocument>,
    pub created: String,
    pub last_used: Option<String>,
}

pub fn insert(vault: &str, access_key: &str, document: AccessKeyDocument) -> AppResult<()> {
    let document = simd_json::to_string(&document).map_app_err(|e| AppError {
        message: "failed to serialize document to JSON".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "document".to_owned() => "AccessKeyDocument".to_owned()
        }),
    })?;

    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    {
        let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            }),
        })?;

        /* borrow checker */
        let query = table.get((vault, access_key)).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                "document".to_owned() => "AccessKeyDocument".to_owned(),
                "vault".to_owned() => vault.to_owned(),
                "access_key".to_owned() => access_key.to_owned()
            }),
        })?;

        if query.is_some() {
            return Err(AppError {
                message: "access key already exists".to_owned(),
                error: None,
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "document".to_owned() => "AccessKeyDocument".to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            });
        }
    };

    {
        let mut table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        table
            .insert((vault, access_key), document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to insert into the DB".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            })?;
    }

    vault::update(vault, vault::UpdateVault::IncreaseAccessKey, &txn)?;

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "access_key".to_owned() => access_key.to_owned()
        }),
    })?;

    Ok(())
}

pub enum DeleteAccessKeyResult {
    Deleted,
    NotFound,
}

pub fn delete(vault: &str, access_key: &str) -> AppResult<DeleteAccessKeyResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let result = {
        let mut table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        if table
            .remove((vault, access_key))
            .map_app_err(|e| AppError {
                message: "failed to delete a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            })?
            .is_some()
        {
            DeleteAccessKeyResult::Deleted
        } else {
            DeleteAccessKeyResult::NotFound
        }
    };

    if matches!(result, DeleteAccessKeyResult::Deleted) {
        vault::update(vault, vault::UpdateVault::DecreaseAccessKey, &txn)?;
    }

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "access_key".to_owned() => access_key.to_owned()
        }),
    })?;

    Ok(result)
}

pub fn find(vault: &str, access_key: &str) -> AppResult<Option<AccessKeyDocument>> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
        }),
    })?;

    if let Some(value) = table.get((vault, access_key)).map_app_err(|e| AppError {
        message: "failed to retrive a document".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "access_key".to_owned() => access_key.to_owned()
        }),
    })? {
        let mut value = value.value().to_owned();

        Ok(
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "document".to_owned() => "AccessKeyDocument".to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            })?,
        )
    } else {
        Ok(None)
    }
}

pub enum ChangePermissionForAccessKeyResult {
    Updated,
    NotFound,
}

pub fn change_permission(
    vault: &str,
    access_key: &str,
    permission: Vec<permission::VaultRoles>,
) -> AppResult<ChangePermissionForAccessKeyResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            }),
        })?;

        /* borrow checker */
        let query = table.get((vault, access_key)).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                "document".to_owned() => "AccessKeyDocument".to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let document: AccessKeyDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "document".to_owned() => "AccessKeyDocument".to_owned()
                }),
            })?;

            Some(document)
        } else {
            None
        }
    };

    let result = if let Some(mut document) = document {
        let mut table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        document.permission = permission;

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "AccessKeyDocument".to_owned(),
                "vault".to_owned() => vault.to_owned(),
                "access_key".to_owned() => access_key.to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert((vault, access_key), document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "document".to_owned() => "AccessKeyDocument".to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            })?;

        ChangePermissionForAccessKeyResult::Updated
    } else {
        ChangePermissionForAccessKeyResult::NotFound
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "document".to_owned() => "AccessKeyDocument".to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "access_key".to_owned() => access_key.to_owned()
        }),
    })?;

    Ok(result)
}

pub enum ChangeSgForAccessKeyResult {
    Updated,
    NotFound,
}

pub fn change_sg(
    vault: &str,
    access_key: &str,
    sg: Vec<AccessKeySgDocument>,
) -> AppResult<ChangeSgForAccessKeyResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            }),
        })?;

        /* borrow checker */
        let query = table.get((vault, access_key)).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                "document".to_owned() => "AccessKeyDocument".to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let document: AccessKeyDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "document".to_owned() => "AccessKeyDocument".to_owned()
                }),
            })?;

            Some(document)
        } else {
            None
        }
    };

    let result = if let Some(mut document) = document {
        let mut table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        document.sg = sg;

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "AccessKeyDocument".to_owned(),
                "vault".to_owned() => vault.to_owned(),
                "access_key".to_owned() => access_key.to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert((vault, access_key), document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "document".to_owned() => "AccessKeyDocument".to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            })?;

        ChangeSgForAccessKeyResult::Updated
    } else {
        ChangeSgForAccessKeyResult::NotFound
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "document".to_owned() => "AccessKeyDocument".to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "access_key".to_owned() => access_key.to_owned()
        }),
    })?;

    Ok(result)
}

pub fn list(vault: &str) -> AppResult<Vec<(String, AccessKeyDocument)>> {
    let mut result = Vec::new();
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
        }),
    })?;

    let mut table_iter = table.iter().map_app_err(|e| AppError {
        message: "failed to iter over table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
        }),
    })?;

    while let Some(entry) = table_iter.next() {
        let (key, value) = entry.map_app_err(|e| AppError {
            message: "failed to iter next value".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                "vault".to_owned() => vault.to_owned(),
            }),
        })?;

        let (access_key_ns, access_key) = key.value();

        if access_key_ns == vault {
            let mut value = value.value().to_owned();

            let value: AccessKeyDocument =
                unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                    message: "failed to deserialize JSON document".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                        "document".to_owned() => "AccessKeyDocument".to_owned(),
                        "vault".to_owned() => vault.to_owned(),
                        "access_key".to_owned() => access_key.to_owned()
                    }),
                })?;

            result.push((access_key.to_owned(), value));
        }
    }

    Ok(result)
}

pub fn purge(vault: &str, txn: &redb::WriteTransaction) -> AppResult<()> {
    let mut to_delete = Vec::new();

    {
        let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        let mut table_iter = table.iter().map_app_err(|e| AppError {
            message: "failed to iter over table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        while let Some(entry) = table_iter.next() {
            let (key, _) = entry.map_app_err(|e| AppError {
                message: "failed to iter next value".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                }),
            })?;

            let (access_key_ns, access_key) = key.value();

            if access_key_ns == vault {
                to_delete.push((access_key_ns.to_string(), access_key.to_string()));
            }
        }
    }

    if !to_delete.is_empty() {
        let mut table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        for key in to_delete {
            table
                .remove((key.0.as_str(), key.1.as_str()))
                .map_app_err(|e| AppError {
                    message: "failed to delete a key".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                        "vault".to_owned() => vault.to_owned(),
                    }),
                })?;
        }
    }

    Ok(())
}

pub fn refresh_access_time(vault: &str, access_key: &str) -> AppResult<()> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        let query = table.get((vault, access_key)).map_app_err(|e| AppError {
            message: "failed to retrive a document".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_owned();

            let document: AccessKeyDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "document".to_owned() => "AccessKeyDocument".to_owned()
                }),
            })?;

            Some(document)
        } else {
            None
        }
    };

    if let Some(mut document) = document {
        let mut table = txn.open_table(ACCESS_KEY_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned()
            }),
        })?;

        let time_now = chrono::Utc::now();

        document.last_used = Some(time_now.to_rfc3339());

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "AccessKeyDocument".to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert((vault, access_key), document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
                    "vault".to_owned() => vault.to_owned(),
                    "access_key".to_owned() => access_key.to_owned()
                }),
            })?;
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => ACCESS_KEY_TABLE.name().to_owned(),
            "vault".to_owned() => vault.to_owned(),
            "access_key".to_owned() => access_key.to_owned()
        }),
    })?;

    Ok(())
}
