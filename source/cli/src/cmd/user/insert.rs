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

use crate::{cmd, outputln, permission, session, term};

#[derive(Debug, Clone, serde::Deserialize)]
struct CommandArgument {
    username: String,
    password: Option<String>,
    role: permission::UserRole,
    sg: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
enum ResponseState {
    Created,
    Exists,
    Denied,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct Response {
    result: ResponseState,
}

pub async fn insert(command_argument: Option<String>) -> anyhow::Result<()> {
    let mut command_argument: CommandArgument =
        cmd::parse_arguments(command_argument.context("missing arguments")?)?;

    if command_argument.password.is_none() {
        let password1 = term::prompt_password("new password")?;
        let password2 = term::prompt_password("repeat password")?;

        if password1 != password2 {
            return Err(anyhow::anyhow!("passwords didn't match"));
        }

        command_argument.password = Some(password1);
    }

    let response: Response =
        session::send_request(cmd::Request::CreateUser(cmd::RequestCreateUser {
            username: command_argument.username,
            password: command_argument
                .password
                .expect("password should have been set"),
            role: command_argument.role,
            sg: command_argument.sg,
        }))
        .await?;

    outputln!(
        "{}",
        serde_json::to_string(&response).context("failed to serialize the response")?
    );

    return Ok(());
}
