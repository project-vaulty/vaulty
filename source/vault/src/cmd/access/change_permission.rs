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
enum ResponseState {
    Updated,
    NotFound,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    result: ResponseState,
}

pub async fn change_permission(
    session: &mut api::Session,
    data: cmd::RequestChangePermissionsForAccessKey,
) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let response =
        match access_keys::change_permission(&data.vault, &data.access_key, data.permission)? {
            access_keys::ChangePermissionForAccessKeyResult::Updated => Response {
                result: ResponseState::Updated,
            },
            access_keys::ChangePermissionForAccessKeyResult::NotFound => Response {
                result: ResponseState::NotFound,
            },
        };

    log!({
        mod: log::Module::Vault,
        ctx: "request to change access key's permission",
        msg: "access key's permission group was changed",
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

    session.send_response(response).await?;

    Ok(())
}
