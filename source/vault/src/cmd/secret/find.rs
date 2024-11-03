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

use maplit::hashmap;

use crate::{
    api,
    app_error::{AppError, AppErrorResult, AppResult},
    cmd, db, log, secrets,
};

#[derive(Debug, Clone, serde::Serialize)]
struct ResponseEntry {
    created: String,
    secret: String,
}

#[derive(Debug, Clone, serde::Serialize)]
enum Response {
    Found(ResponseEntry),
    NotFound,
}

pub async fn find(session: &mut api::Session, data: cmd::RequestFindSecret) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    if let Some(document) = db::secret::find(&data.vault, &data.secret_name)? {
        let secret = base64_simd::STANDARD
            .decode_to_vec(document.secret)
            .map_app_err(|e| AppError {
                message: "failed to decode the secret".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "secret".to_owned() => data.secret_name.clone(),
                    "vault".to_owned() => data.vault.clone(),
                }),
            })?;

        let secret = secrets::decrypt(&secret)?;
        let secret = base64_simd::STANDARD.encode_to_string(secret);

        let entry = ResponseEntry {
            created: document.created.clone(),
            secret,
        };

        log!({
            mod: log::Module::Vault,
            ctx: "request to find a secret",
            msg: "secret found",
            tags: [
                "api", "secret", "request"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                vault: data.vault.clone(),
                secret_name: data.secret_name.clone()
            }
        });

        session.send_response(&Response::Found(entry)).await?;
    } else {
        log!({
            mod: log::Module::Vault,
            ctx: "request to find a secret",
            msg: "secret was not found",
            tags: [
                "api", "secret", "request"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                vault: data.vault,
                secret_name: data.secret_name
            }
        });

        session.send_response(&Response::NotFound).await?;
    }

    Ok(())
}
