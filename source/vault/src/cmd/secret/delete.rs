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
enum ResponseState {
    Deleted,
    NotFound,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    result: ResponseState,
}

pub async fn delete(session: &mut api::Session, data: cmd::RequestDeleteSecret) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let result = match db::secret::delete(&data.vault, &data.secret_name)? {
        db::secret::DeleteSecretResult::Deleted => ResponseState::Deleted,
        db::secret::DeleteSecretResult::NotFound => ResponseState::NotFound,
    };

    log!({
        mod: log::Module::Vault,
        ctx: "request to delete secret",
        msg: "secret deleted",
        tags: [
            "api", "secret", "request"
        ],
        attr: {
            ip: session.friendly_ip.clone(),
            user: executer_username.clone(),
            vault: data.vault,
            secret_name: data.secret_name.clone()
        }
    });

    session.send_response(&Response { result }).await?;

    Ok(())
}
