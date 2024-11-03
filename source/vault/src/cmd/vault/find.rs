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

use crate::{api, app_error::AppResult, cmd, db, log};

#[derive(Debug, Clone, serde::Serialize)]
struct ResponseEntry {
    vault: String,
    created: String,
    secrets_count: i64,
    access_keys_count: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
enum Response {
    Found(ResponseEntry),
    NotFound,
}

pub async fn find(session: &mut api::Session, data: cmd::RequestFindVault) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    if let Some(document) = db::vault::find(&data.vault)? {
        log!({
            mod: log::Module::Vault,
            ctx: "request to find a vault",
            msg: "vault found",
            tags: [
                "api", "vault", "request"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                vault: data.vault.clone(),
            }
        });

        session
            .send_response(&Response::Found(ResponseEntry {
                vault: document.vault,
                created: document.created,
                secrets_count: document.secrets_count,
                access_keys_count: document.access_keys_count,
            }))
            .await?;
    } else {
        log!({
            mod: log::Module::Vault,
            ctx: "request to find a vault",
            msg: "vault was not found",
            tags: [
                "api", "vault", "request", "error"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
            }
        });

        session.send_response(&Response::NotFound).await?;
    }

    Ok(())
}
