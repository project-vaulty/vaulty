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

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum UserRole {
    Admin,
    User,
}

impl ToString for UserRole {
    fn to_string(&self) -> String {
        match self {
            UserRole::Admin => "Admin".to_owned(),
            UserRole::User => "User".to_owned(),
        }
    }
}

impl Into<json::JsonValue> for UserRole {
    fn into(self) -> json::JsonValue {
        match self {
            Self::Admin => json::JsonValue::String("Admin".to_string()),
            Self::User => json::JsonValue::String("User".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VaultRoles {
    ListSecrets,
    DeleteSecrets,
    CreateSecrets,
    DecryptSecrets,
}

impl ToString for VaultRoles {
    fn to_string(&self) -> String {
        match self {
            VaultRoles::ListSecrets => "ListSecrets".to_owned(),
            VaultRoles::DeleteSecrets => "DeleteSecrets".to_owned(),
            VaultRoles::CreateSecrets => "CreateSecrets".to_owned(),
            VaultRoles::DecryptSecrets => "DecryptSecrets".to_owned(),
        }
    }
}

impl Into<json::JsonValue> for VaultRoles {
    fn into(self) -> json::JsonValue {
        match self {
            Self::ListSecrets => json::JsonValue::String("ListSecrets".to_string()),
            Self::DeleteSecrets => json::JsonValue::String("DeleteSecrets".to_string()),
            Self::CreateSecrets => json::JsonValue::String("CreateSecrets".to_string()),
            Self::DecryptSecrets => json::JsonValue::String("DecryptSecrets".to_string()),
        }
    }
}
