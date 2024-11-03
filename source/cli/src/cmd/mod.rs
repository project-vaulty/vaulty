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

pub mod access;
pub mod secret;
pub mod user;
pub mod vault;

use anyhow::Context;

use crate::permission;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestCreateUser {
    pub username: String,
    pub password: String,
    pub role: permission::UserRole,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestFindUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestDeleteUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestPromoteUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestDemoteUser {
    pub username: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestChangePasswordForUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestChangeSgForUser {
    pub username: String,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestCreateAccessKey {
    pub vault: String,
    pub permission: Vec<permission::VaultRoles>,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestListAccessKeys {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestFindAccessKey {
    pub vault: String,
    pub access_key: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestDeleteAccessKey {
    pub vault: String,
    pub access_key: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestChangePermissionsForAccessKey {
    pub vault: String,
    pub access_key: String,
    pub permission: Vec<permission::VaultRoles>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestChangeSgForAccessKey {
    pub vault: String,
    pub access_key: String,
    pub sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestFindVault {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestDeleteVault {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestInsertSecret {
    pub secret_name: String,
    pub vault: String,
    pub data: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestListSecrets {
    pub vault: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestFindSecret {
    pub vault: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestDeleteSecret {
    pub vault: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
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

pub fn parse_arguments<T>(arguments: String) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    Ok(serde_yaml::from_str(&arguments).context("invalid arguments")?)
}
