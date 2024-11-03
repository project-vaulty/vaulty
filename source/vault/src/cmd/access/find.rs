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

use crate::{api, app_error::AppResult, cmd, db, log, permission};

#[derive(Debug, Clone, serde::Serialize)]
struct ResponseEntry {
    access_key: String,
    permission: Vec<permission::VaultRoles>,
    sg: Vec<String>,
    created: String,
    last_used: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
enum Response {
    Found(ResponseEntry),
    NotFound,
}

pub async fn find(session: &mut api::Session, data: cmd::RequestFindAccessKey) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    if let Some(document) = db::access::find(&data.vault, &data.access_key)? {
        let entry = ResponseEntry {
            access_key: data.access_key.clone(),
            permission: document.permission,
            sg: document
                .sg
                .iter()
                .map(|v| format!("{}/{}", v.network, v.prefix))
                .collect(),
            created: document.created,
            last_used: document.last_used,
        };

        log!({
            mod: log::Module::Vault,
            ctx: "request to find access key",
            msg: "access key found",
            tags: [
                "api", "access_key", "request"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                vault: data.vault,
                access_key: data.access_key.clone()
            }
        });

        session.send_response(&Response::Found(entry)).await?;
    } else {
        log!({
            mod: log::Module::Vault,
            ctx: "request to find a access key",
            msg: "access key was not found",
            tags: [
                "api", "access_key", "request", "failed"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                vault: data.vault,
                access_key: data.access_key
            }
        });

        session.send_response(&Response::NotFound).await?;
    }

    Ok(())
}
