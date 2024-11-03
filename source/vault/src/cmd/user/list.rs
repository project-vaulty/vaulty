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

use crate::{api, app_error::AppResult, db, log, permission};

#[derive(Debug, Clone, serde::Serialize)]
struct ResponseEntry {
    username: String,
    role: permission::UserRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_login: Option<String>,
    sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    users: Vec<ResponseEntry>,
}

pub async fn list(session: &mut api::Session) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let users_list = db::user::list()?;

    log!({
        mod: log::Module::Vault,
        ctx: "request to list users",
        msg: "users listed",
        tags: [
            "api", "user", "request", "error"
        ],
        attr: {
            ip: session.friendly_ip.clone(),
            user: executer_username.clone(),
        }
    });

    session
        .send_response(&Response {
            users: users_list
                .iter()
                .map(|v| ResponseEntry {
                    username: v.username.clone(),
                    role: v.role,
                    last_login: v.last_login.clone(),
                    sg: v.sg.clone(),
                })
                .collect(),
        })
        .await?;

    Ok(())
}
