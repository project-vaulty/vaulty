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

use crate::{api, app_error::AppResult, db, log};

#[derive(Debug, Clone, serde::Serialize)]
struct ResponseEntry {
    vault: String,
    created: String,
    secrets_count: i64,
    access_keys_count: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    vaults: Vec<ResponseEntry>,
}

pub async fn list(session: &mut api::Session) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let result = db::vault::list()?;

    log!({
        mod: log::Module::Vault,
        ctx: "request to list vaults",
        msg: "vaults listed",
        tags: [
            "api", "vault", "request", "error"
        ],
        attr: {
            ip: session.friendly_ip.clone(),
            user: executer_username.clone(),
        }
    });

    session
        .send_response(&Response {
            vaults: result
                .iter()
                .map(|v| ResponseEntry {
                    vault: v.vault.clone(),
                    created: v.created.clone(),
                    secrets_count: v.secrets_count,
                    access_keys_count: v.access_keys_count,
                })
                .collect(),
        })
        .await?;

    Ok(())
}
