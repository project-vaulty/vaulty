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
enum ResponseResult {
    Deleted,
    NotFound,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    result: ResponseResult,
}

pub async fn delete(session: &mut api::Session, data: cmd::RequestDeleteVault) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let result = match db::vault::delete(&data.vault)? {
        db::vault::DeleteVaultResult::Deleted => ResponseResult::Deleted,
        db::vault::DeleteVaultResult::NotFound => ResponseResult::NotFound,
    };

    log!({
        mod: log::Module::Vault,
        ctx: "request to delete a vault",
        msg: "vault deleted",
        tags: [
            "api", "vault", "request"
        ],
        attr: {
            ip: session.friendly_ip.clone(),
            user: executer_username.clone(),
            vault: data.vault.clone(),
        }
    });

    session.send_response(&Response { result }).await?;

    Ok(())
}
