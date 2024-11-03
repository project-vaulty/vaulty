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
struct Response {
    access_keys: Vec<ResponseEntry>,
}

pub async fn list(session: &mut api::Session, data: cmd::RequestListAccessKeys) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let mut result = Vec::new();
    let documents = db::access::list(&data.vault)?;

    for (access_key, document) in documents {
        result.push(ResponseEntry {
            access_key,
            permission: document.permission,
            sg: document
                .sg
                .iter()
                .map(|v| format!("{}/{}", v.network, v.prefix))
                .collect(),
            created: document.created,
            last_used: document.last_used,
        });
    }

    log!({
        mod: log::Module::Vault,
        ctx: "request to list access keys",
        msg: "access keys listed",
        tags: [
            "api", "access_key", "request"
        ],
        attr: {
            ip: session.friendly_ip.clone(),
            user: executer_username.clone(),
            vault: data.vault,
        }
    });

    session
        .send_response(&Response {
            access_keys: result,
        })
        .await?;

    Ok(())
}
