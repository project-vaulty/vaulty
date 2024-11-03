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

use crate::{access_keys, api, app_error::AppResult, cmd, log};

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    access_key: String,
    secret_access_key: String,
}

pub async fn insert(
    session: &mut api::Session,
    data: cmd::RequestCreateAccessKey,
) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let document = access_keys::create(&data.vault, data.sg, data.permission)?;

    log!({
        mod: log::Module::Vault,
        ctx: "request to insert a access key",
        msg: "access key inserted",
        tags: [
            "api", "access_key", "request"
        ],
        attr: {
            ip: session.friendly_ip.clone(),
            user: executer_username.clone(),
            vault: data.vault,
            access_key: document.access_key.clone()
        }
    });

    session
        .send_response(&Response {
            access_key: document.access_key,
            secret_access_key: document.secret_access_key,
        })
        .await?;

    Ok(())
}
