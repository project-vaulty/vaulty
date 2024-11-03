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

use crate::permission;

pub mod access;
pub mod secret;
pub mod user;
pub mod vault;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestCreateUser {
    pub username: String,
    pub password: String,
    pub role: permission::UserRole,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestFindUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestDeleteUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestPromoteUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestDemoteUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestChangePasswordForUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestChangeSgForUser {
    pub username: String,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestCreateAccessKey {
    pub vault: String,
    pub permission: Vec<permission::VaultRoles>,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestListAccessKeys {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestFindAccessKey {
    pub vault: String,
    pub access_key: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestDeleteAccessKey {
    pub vault: String,
    pub access_key: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestChangePermissionsForAccessKey {
    pub vault: String,
    pub access_key: String,
    pub permission: Vec<permission::VaultRoles>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestChangeSgForAccessKey {
    pub vault: String,
    pub access_key: String,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestFindVault {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestDeleteVault {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestInsertSecret {
    pub secret_name: String,
    pub vault: String,
    pub data: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestListSecrets {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestFindSecret {
    pub vault: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RequestDeleteSecret {
    pub vault: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub enum Request {
    CreateUser(RequestCreateUser),
    ListUsers(),
    FindUser(RequestFindUser),
    DeleteUser(RequestDeleteUser),
    PromoteUser(RequestPromoteUser),
    DemoteUser(RequestDemoteUser),
    ChangePasswordForUser(RequestChangePasswordForUser),
    ChangeSgForUser(RequestChangeSgForUser),
    CreateAccessKey(RequestCreateAccessKey),
    ListAccessKeys(RequestListAccessKeys),
    FindAccessKey(RequestFindAccessKey),
    DeleteAccessKey(RequestDeleteAccessKey),
    ChangePermissionForAccessKey(RequestChangePermissionsForAccessKey),
    ChangeSgForAccessKey(RequestChangeSgForAccessKey),
    ListVaults(),
    FindVault(RequestFindVault),
    DeleteVault(RequestDeleteVault),
    InsertSecret(RequestInsertSecret),
    ListSecrets(RequestListSecrets),
    FindSecret(RequestFindSecret),
    DeleteSecret(RequestDeleteSecret),
}

impl Request {
    pub fn to_command_string(&self) -> String {
        match self {
            Request::CreateUser(_) => "CreateUser".to_string(),
            Request::ListUsers() => "ListUsers".to_string(),
            Request::FindUser(_) => "FindUser".to_string(),
            Request::DeleteUser(_) => "DeleteUser".to_string(),
            Request::PromoteUser(_) => "PromoteUser".to_string(),
            Request::DemoteUser(_) => "DemoteUser".to_string(),
            Request::ChangePasswordForUser(_) => "ChangePasswordForUser".to_string(),
            Request::ChangeSgForUser(_) => "ChangeSgForUser".to_string(),
            Request::CreateAccessKey(_) => "CreateAccessKey".to_string(),
            Request::ListAccessKeys(_) => "ListAccessKeys".to_string(),
            Request::FindAccessKey(_) => "FindAccessKey".to_string(),
            Request::DeleteAccessKey(_) => "DeleteAccessKey".to_string(),
            Request::ChangePermissionForAccessKey(_) => "ChangePermissionForAccessKey".to_string(),
            Request::ChangeSgForAccessKey(_) => "ChangeSgForAccessKey".to_string(),
            Request::ListVaults() => "ListVaults".to_string(),
            Request::FindVault(_) => "FindVault".to_string(),
            Request::DeleteVault(_) => "DeleteVault".to_string(),
            Request::InsertSecret(_) => "InsertSecret".to_string(),
            Request::ListSecrets(_) => "ListSecrets".to_string(),
            Request::FindSecret(_) => "FindSecret".to_string(),
            Request::DeleteSecret(_) => "DeleteSecret".to_string(),
        }
    }
}
