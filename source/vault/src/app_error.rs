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

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr: Option<std::collections::HashMap<String, String>>,
}

impl Into<json::JsonValue> for AppError {
    fn into(self) -> json::JsonValue {
        json::object! {
            message: self.message,
            error: self.error,
            attr: self.attr,
        }
    }
}

pub trait AppErrorResult<T, E> {
    fn map_app_err<F>(self, function: F) -> Result<T, AppError>
    where
        F: FnOnce(E) -> AppError;
}

impl<T, E> AppErrorResult<T, E> for Result<T, E> {
    fn map_app_err<F>(self, function: F) -> Result<T, AppError>
    where
        F: FnOnce(E) -> AppError,
    {
        match self {
            Ok(value) => Ok(value),
            Err(e) => Err(function(e)),
        }
    }
}

pub trait AppErrorToAnyhowResult<T> {
    fn to_anyhow_error(self) -> anyhow::Result<T>;
}

impl<T> AppErrorToAnyhowResult<T> for AppResult<T> {
    fn to_anyhow_error(self) -> anyhow::Result<T> {
        match self {
            Ok(value) => Ok(value),
            Err(e) => Err(anyhow::anyhow!("{}", e.error.unwrap_or(e.message))),
        }
    }
}

pub trait AppErrorOption<T> {
    fn context_app_err<F>(self, function: F) -> Result<T, AppError>
    where
        F: FnOnce() -> AppError;
}

impl<T> AppErrorOption<T> for Option<T> {
    fn context_app_err<F>(self, function: F) -> Result<T, AppError>
    where
        F: FnOnce() -> AppError,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(function()),
        }
    }
}
