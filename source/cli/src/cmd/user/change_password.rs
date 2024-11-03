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

use crate::{cmd, outputln, session, term};

#[derive(Debug, Clone, serde::Deserialize)]
struct CommandArgument {
    password: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum ResponseResult {
    Changed,
    NotFound,
    Denied,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Response {
    result: ResponseResult,
}

pub async fn change_password(
    username: String,
    command_argument: Option<String>,
) -> anyhow::Result<()> {
    let password = if let Some(command_argument) = command_argument {
        let command_argument: CommandArgument = cmd::parse_arguments(command_argument)?;

        command_argument.password
    } else {
        let password1 = term::prompt_password("new password")?;
        let password2 = term::prompt_password("repeat password")?;

        if password1 != password2 {
            return Err(anyhow::anyhow!("passwords didn't match"));
        }

        password1
    };

    let response: Response = session::send_request(cmd::Request::ChangePasswordForUser(
        cmd::RequestChangePasswordForUser {
            username: username,
            password: password,
        },
    ))
    .await?;

    outputln!(
        "{}",
        serde_json::to_string(&response).context("failed to serialize the response")?
    );

    return Ok(());
}
