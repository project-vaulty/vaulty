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

use super::{DATABASE, USERS_TABLE};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSgDocument {
    pub network: String,
    pub prefix: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserDocument {
    pub password: String,
    pub role: permission::UserRole,
    pub last_login: Option<String>,
    pub sg: Vec<UserSgDocument>,
}

pub enum InsertUserResult {
    Created,
    Exists,
}

pub fn insert(username: &str, document: UserDocument) -> AppResult<InsertUserResult> {
    let document = simd_json::to_string(&document).map_app_err(|e| AppError {
        message: "failed to serialize document to JSON".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "document".to_owned() => "UserDocument".to_owned()
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
        let mut table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        if table
            .get(&username)
            .map_app_err(|e| AppError {
                message: "failed to open table".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?
            .is_some()
        {
            return Ok(InsertUserResult::Exists);
        }

        let _ = table
            .insert(username, document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to insert a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?;
    }

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })?;

    Ok(InsertUserResult::Created)
}

pub enum DeleteUserResult {
    Deleted,
    NotFound,
}

pub fn delete(username: &str) -> AppResult<DeleteUserResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let result = {
        let mut table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        if table
            .remove(&username)
            .map_app_err(|e| AppError {
                message: "failed to delete a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?
            .is_some()
        {
            DeleteUserResult::Deleted
        } else {
            DeleteUserResult::NotFound
        }
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })?;

    Ok(result)
}

pub fn find(username: &str) -> AppResult<Option<UserDocument>> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned()
        }),
    })?;

    if let Some(value) = table.get(&username).map_app_err(|e| AppError {
        message: "failed to retrive a document".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })? {
        let mut value = value.value().to_owned();

        Ok(
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "document".to_owned() => "UserDocument".to_owned(),
                    "username".to_owned() => username.to_owned(),
                }),
            })?,
        )
    } else {
        Ok(None)
    }
}

pub struct ListUsersResult {
    pub username: String,
    pub role: permission::UserRole,
    pub last_login: Option<String>,
    pub sg: Vec<String>,
}

pub fn list() -> AppResult<Vec<ListUsersResult>> {
    let mut result = Vec::new();
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_read()
        .map_app_err(|e| AppError {
            message: "failed to begin read transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
        message: "failed to open table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned()
        }),
    })?;

    let mut table_iter = table.iter().map_app_err(|e| AppError {
        message: "failed to iter over table".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned()
        }),
    })?;

    while let Some(entry) = table_iter.next() {
        let (key, value) = entry.map_app_err(|e| AppError {
            message: "failed to iter next value".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        let username = key.value().to_owned();
        let mut value = value.value().to_owned();

        let user: UserDocument =
            unsafe { simd_json::from_str(&mut value) }.map_app_err(|e| AppError {
                message: "failed to deserialize JSON document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "document".to_owned() => "UserDocument".to_owned(),
                    "username".to_owned() => username.clone(),
                }),
            })?;

        result.push(ListUsersResult {
            username: key.value().to_owned(),
            role: user.role,
            last_login: user.last_login,
            sg: user
                .sg
                .iter()
                .map(|v| format!("{}/{}", v.network, v.prefix))
                .collect(),
        });
    }

    Ok(result)
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ChangeUserRoleResult {
    Promoted,
    Demoted,
    NoChange,
    NotFound,
}

pub fn change_role(username: &str, role: &permission::UserRole) -> AppResult<ChangeUserRoleResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        /* borrow checker */
        let query = table.get(&username).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned(),
                "username".to_owned() => username.to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let document: UserDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                    message: "failed to deserialize JSON document".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "document".to_owned() => "UserDocument".to_owned()
                    }),
                })?;

            Some(document)
        } else {
            None
        }
    };

    let result = if let Some(mut document) = document {
        let mut table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        let result = match document.role {
            permission::UserRole::Admin => match &role {
                permission::UserRole::Admin => ChangeUserRoleResult::NoChange,
                permission::UserRole::User => ChangeUserRoleResult::Demoted,
            },
            permission::UserRole::User => match &role {
                permission::UserRole::Admin => ChangeUserRoleResult::Promoted,
                permission::UserRole::User => ChangeUserRoleResult::NoChange,
            },
        };

        document.role = role.clone();

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "UserDocument".to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert(&username, document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?;

        result
    } else {
        ChangeUserRoleResult::NotFound
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })?;

    Ok(result)
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ChangeUserPasswordResult {
    Changed,
    NotFound,
}

pub fn change_password(username: &str, password: &str) -> AppResult<ChangeUserPasswordResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        /* borrow checker */
        let query = table.get(&username).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned(),
                "username".to_owned() => username.to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let document: UserDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                    message: "failed to deserialize JSON document".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "document".to_owned() => "UserDocument".to_owned()
                    }),
                })?;

            Some(document)
        } else {
            None
        }
    };

    let result = if let Some(mut document) = document {
        let mut table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        document.password = password.to_string();

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "UserDocument".to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert(&username, document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?;

        ChangeUserPasswordResult::Changed
    } else {
        ChangeUserPasswordResult::NotFound
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })?;

    Ok(result)
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ChangeUserSgResult {
    Changed,
    NotFound,
}

pub fn change_sg(username: &str, sg: Vec<UserSgDocument>) -> AppResult<ChangeUserSgResult> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        /* borrow checker */
        let query = table.get(&username).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned(),
                "username".to_owned() => username.to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let document: UserDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                    message: "failed to deserialize JSON document".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "document".to_owned() => "UserDocument".to_owned()
                    }),
                })?;

            Some(document)
        } else {
            None
        }
    };

    let result = if let Some(mut document) = document {
        let mut table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        document.sg = sg;

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "UserDocument".to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert(&username, document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?;

        ChangeUserSgResult::Changed
    } else {
        ChangeUserSgResult::NotFound
    };

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })?;

    Ok(result)
}

pub fn refresh_last_active(username: &str) -> AppResult<()> {
    let txn = unsafe { DATABASE.as_ref().expect("db.rs hasn't been initialized") }
        .begin_write()
        .map_app_err(|e| AppError {
            message: "failed to begin write transaction".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let document = {
        let table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        /* borrow checker */
        let query = table.get(&username).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned(),
                "username".to_owned() => username.to_owned()
            }),
        })?;

        if let Some(document) = query {
            let mut document_value = document.value().to_string();

            let document: UserDocument = unsafe { simd_json::from_str(&mut document_value) }
                .map_app_err(|e| AppError {
                    message: "failed to deserialize JSON document".to_owned(),
                    error: Some(e.to_string()),
                    attr: Some(hashmap! {
                        "document".to_owned() => "UserDocument".to_owned()
                    }),
                })?;

            Some(document)
        } else {
            None
        }
    };

    if let Some(mut document) = document {
        let mut table = txn.open_table(USERS_TABLE).map_app_err(|e| AppError {
            message: "failed to open table".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "table".to_owned() => USERS_TABLE.name().to_owned()
            }),
        })?;

        let timenow: chrono::DateTime<chrono::Local> = chrono::Local::now();

        document.last_login = Some(timenow.to_rfc3339());

        let document = simd_json::to_string(&document).map_app_err(|e| AppError {
            message: "failed to serialize document to JSON".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "document".to_owned() => "UserDocument".to_owned()
            }),
        })?;

        /* borrow checker */
        let _ = table
            .insert(&username, document.as_str())
            .map_app_err(|e| AppError {
                message: "failed to update a document".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "table".to_owned() => USERS_TABLE.name().to_owned(),
                    "username".to_owned() => username.to_owned()
                }),
            })?;
    }

    txn.commit().map_app_err(|e| AppError {
        message: "failed to commit to the DB".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "table".to_owned() => USERS_TABLE.name().to_owned(),
            "username".to_owned() => username.to_owned(),
        }),
    })?;

    Ok(())
}
