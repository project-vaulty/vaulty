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

use crate::{
    api,
    app_error::{AppError, AppErrorResult, AppResult},
    cmd, db, log, secrets,
};

#[derive(Debug, Clone, serde::Serialize)]
enum ResponseResult {
    Inserted,
    Updated,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    result: ResponseResult,
}

pub async fn insert(session: &mut api::Session, data: cmd::RequestInsertSecret) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let secret = base64_simd::STANDARD
        .decode_to_vec(data.data)
        .map_app_err(|e| AppError {
            message: "failed to decode the data".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    let secret = secrets::encrypt(&secret)?;
    let secret = base64_simd::STANDARD.encode_to_string(secret);

    let time_now = chrono::Utc::now();

    let result = match db::secret::insert(
        &data.vault,
        &data.secret_name,
        db::secret::SecretDocument {
            created: time_now.to_rfc3339(),
            secret: secret,
        },
    )? {
        db::secret::InsertSecretResult::Inserted => ResponseResult::Inserted,
        db::secret::InsertSecretResult::Updated => ResponseResult::Updated,
    };

    log!({
        mod: log::Module::Vault,
        ctx: "request to insert a secret",
        msg: "secret inserted",
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
