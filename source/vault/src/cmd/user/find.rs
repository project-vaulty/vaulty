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
    username: String,
    role: permission::UserRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_login: Option<String>,
    sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
enum Response {
    Found(ResponseEntry),
    NotFound,
}

pub async fn find(session: &mut api::Session, data: cmd::RequestFindUser) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    if let Some(user) = db::user::find(&data.username)? {
        log!({
            mod: log::Module::Vault,
            ctx: "request to find a user",
            msg: "user found",
            tags: [
                "api", "user", "request"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                target_user: data.username.clone()
            }
        });

        session
            .send_response(&Response::Found(ResponseEntry {
                username: data.username,
                role: user.role,
                last_login: user.last_login,
                sg: user
                    .sg
                    .iter()
                    .map(|v| format!("{}/{}", v.network, v.prefix))
                    .collect(),
            }))
            .await?;
    } else {
        log!({
            mod: log::Module::Vault,
            ctx: "request to find a user",
            msg: "user was not found",
            tags: [
                "api", "user", "request", "error"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                target_user: data.username.clone(),
            }
        });

        session.send_response(&Response::NotFound).await?;
    }

    Ok(())
}
