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

use anyhow::Context;

use crate::{
    cmd::{self, RequestFindSecret},
    outputln, session,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CommandArgument {
    decode: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ResponseEntry {
    created: String,
    secret: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum Response {
    Found(ResponseEntry),
    NotFound,
}

pub async fn find(
    vault: String,
    secret_name: String,
    command_argument: Option<String>,
) -> anyhow::Result<()> {
    let decode = {
        if let Some(command_argument) = command_argument {
            let command_argument: CommandArgument = cmd::parse_arguments(command_argument)?;

            if let Some(decode) = command_argument.decode {
                decode
            } else {
                false
            }
        } else {
            false
        }
    };

    let response: Response = session::send_request(cmd::Request::FindSecret(RequestFindSecret {
        vault,
        secret_name,
    }))
    .await?;

    if let Response::Found(mut document) = response {
        if decode {
            let data = base64_simd::STANDARD
                .decode_to_vec(document.secret)
                .context("failed to decode the response")?;
            let data = String::from_utf8_lossy(&data);

            document.secret = data.to_string();

            outputln!(
                "{}",
                serde_json::to_string(&document).context("failed to serialize the response")?
            );
        } else {
            outputln!(
                "{}",
                serde_json::to_string(&document).context("failed to serialize the response")?
            );
        }
    }

    Ok(())
}
