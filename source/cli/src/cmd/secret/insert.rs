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

use std::io::Read;

use anyhow::Context;

use crate::{
    cmd::{self, RequestInsertSecret},
    outputln, session,
};

const MAXIMUM_DATA_SIZE: usize = 128 * 1042 * 1024 - 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CommandArgument {
    text: Option<String>,
    binary: Option<String>,
    file: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum ResponseResult {
    Inserted,
    Updated,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Response {
    result: ResponseResult,
}

pub async fn insert(
    vault: String,
    secret_name: String,
    command_argument: Option<String>,
) -> anyhow::Result<()> {
    let command_argument: CommandArgument =
        cmd::parse_arguments(command_argument.context("missing arguments")?)?;

    if command_argument.text.is_some()
        && (command_argument.binary.is_some() || command_argument.file.is_some())
    {
        return Err(anyhow::anyhow!(
            "specify either text, binary or file fields"
        ));
    } else if command_argument.binary.is_some()
        && (command_argument.text.is_some() || command_argument.file.is_some())
    {
        return Err(anyhow::anyhow!(
            "specify either text, binary or file fields"
        ));
    } else if command_argument.file.is_some()
        && (command_argument.text.is_some() || command_argument.binary.is_some())
    {
        return Err(anyhow::anyhow!(
            "specify either text, binary or file fields"
        ));
    }

    let data = if let Some(data) = command_argument.text {
        base64_simd::STANDARD.encode_to_string(data)
    } else if let Some(data) = command_argument.binary {
        data
    } else if let Some(filename) = command_argument.file {
        let mut content = Vec::new();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&filename)
            .context(format!("failed to open '{filename}' for reading"))?;

        let _ = file
            .read_to_end(&mut content)
            .context(format!("failed to read from {filename}"))?;

        base64_simd::STANDARD.encode_to_string(content)
    } else {
        return Err(anyhow::anyhow!("invalid data"));
    };

    if data.len() > MAXIMUM_DATA_SIZE {
        return Err(anyhow::anyhow!("the data is too big"));
    }

    let response: Response =
        session::send_request(cmd::Request::InsertSecret(RequestInsertSecret {
            vault,
            secret_name,
            data,
        }))
        .await?;

    outputln!(
        "{}",
        serde_json::to_string(&response).context("failed to serialize the users")?
    );

    Ok(())
}
