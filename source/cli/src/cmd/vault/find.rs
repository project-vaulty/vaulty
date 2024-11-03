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

use anyhow::Context;

use crate::{
    cmd::{self, RequestFindVault},
    outputln, session,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ResponseEntry {
    vault: String,
    created: String,
    secrets_count: i64,
    access_keys_count: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum Response {
    Found(ResponseEntry),
    NotFound,
}

pub async fn find(vault: String) -> anyhow::Result<()> {
    let response: Response =
        session::send_request(cmd::Request::FindVault(RequestFindVault { vault })).await?;

    if let Response::Found(user) = response {
        outputln!(
            "{}",
            serde_json::to_string(&user).context("failed to serialize the response")?
        )
    }

    Ok(())
}
