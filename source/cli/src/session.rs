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
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tungstenite::{http::StatusCode, Message};

use crate::{cmd, cmdline, errorln, outputln, parser, term};

static COMMAND_STREAM_TX: once_cell::sync::Lazy<
    Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<Message>>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));
static COMMAND_STREAM_RX: once_cell::sync::Lazy<
    Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Message>>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));

async fn commands_handle(
    command_input_object: &mut term::CommandInput,
    server_name: &str,
    username: &str,
) -> anyhow::Result<()> {
    let input = match command_input_object.prompt(&format!("\n{} ({}): ", server_name, username)) {
        Ok(value) => value,
        Err(rustyline::error::ReadlineError::Interrupted) => {
            outputln!("press ctrl+d to exit");

            return Ok(());
        }
        Err(rustyline::error::ReadlineError::Eof) => {
            std::process::exit(0);
        }
        Err(err) => {
            return Err(anyhow::anyhow!("{}", err.to_string()));
        }
    };

    let command = parser::parse(&input).map_err(|e| anyhow::anyhow!("{}", e.to_string()))?;

    let command: Vec<(&str, Option<String>)> = command
        .iter()
        .map(|(command, value)| (command.as_str(), value.clone()))
        .collect();

    match &command[..] {
        [("user", None), ("insert", arg)] => return cmd::user::insert(arg.clone()).await,
        [("user", None), ("list", None)] => return cmd::user::list().await,
        [("user", None), (username, None), ("find", None)] => {
            return cmd::user::find(username.to_string()).await
        }
        [("user", None), (username, None), ("delete", None)] => {
            return cmd::user::delete(username.to_string()).await
        }
        [("user", None), (username, None), ("changePassword", arg)] => {
            return cmd::user::change_password(username.to_string(), arg.clone()).await
        }
        [("user", None), (username, None), ("changeSg", arg)] => {
            return cmd::user::change_sg(username.to_string(), arg.clone()).await
        }
        [("user", None), (username, None), ("promote", None)] => {
            return cmd::user::promote(username.to_string()).await
        }
        [("user", None), (username, None), ("demote", None)] => {
            return cmd::user::demote(username.to_string()).await
        }
        [("vault", None), ("list", None)] => return cmd::vault::list().await,
        [("vault", None), (vault, None), ("find", None)] => {
            return cmd::vault::find(vault.to_string()).await
        }
        [("vault", None), (vault, None), ("delete", None)] => {
            return cmd::vault::delete(vault.to_string()).await
        }
        [("access", None), (vault, None), ("list", None)] => {
            return cmd::access::list(vault.to_string()).await
        }
        [("access", None), (vault, None), (access_key, None), ("find", None)] => {
            return cmd::access::find(vault.to_string(), access_key.to_string()).await
        }
        [("access", None), (vault, None), ("insert", arg)] => {
            return cmd::access::insert(vault.to_string(), arg.clone()).await
        }
        [("access", None), (vault, None), (access_key, None), ("delete", None)] => {
            return cmd::access::delete(vault.to_string(), access_key.to_string()).await
        }
        [("access", None), (vault, None), (access_key, None), ("changePermission", arg)] => {
            return cmd::access::change_permission(
                vault.to_string(),
                access_key.to_string(),
                arg.clone(),
            )
            .await
        }
        [("access", None), (vault, None), (access_key, None), ("changeSg", arg)] => {
            return cmd::access::change_sg(vault.to_string(), access_key.to_string(), arg.clone())
                .await
        }
        [("secret", None), (vault, None), ("list", None)] => {
            return cmd::secret::list(vault.to_string()).await
        }
        [("secret", None), (vault, None), (secret_name, None), ("insert", arg)] => {
            return cmd::secret::insert(vault.to_string(), secret_name.to_string(), arg.clone())
                .await
        }
        [("secret", None), (vault, None), (secret_name, None), ("find", arg)] => {
            return cmd::secret::find(vault.to_string(), secret_name.to_string(), arg.clone()).await
        }
        [("secret", None), (vault, None), (secret_name, None), ("delete", None)] => {
            return cmd::secret::delete(vault.to_string(), secret_name.to_string()).await
        }
        _ => {}
    }

    return Err(anyhow::anyhow!("unknown command"));
}

async fn login(username: &str, password: &str) -> anyhow::Result<String> {
    #[derive(Debug, Clone, serde::Serialize)]
    struct Request {
        username: String,
        password: String,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    enum ResponseResult {
        Granted,
        Denied,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    struct Response {
        result: ResponseResult,
        node_name: Option<String>,
    }

    let response: Response = send_request(&Request {
        username: username.to_owned(),
        password: password.to_owned(),
    })
    .await?;

    match response.result {
        ResponseResult::Granted => Ok(response.node_name.unwrap_or("N/A".to_owned())),
        ResponseResult::Denied => Err(anyhow::anyhow!("invalid credentials")),
    }
}

pub async fn send_request<'a, Input, Output>(data: Input) -> anyhow::Result<Output>
where
    Input: serde::Serialize,
    Output: serde::de::DeserializeOwned,
{
    let request = serde_json::to_string(&data).context("failed to serialize the request")?;

    let mut rx = COMMAND_STREAM_RX.lock().await;
    let rx = rx.as_mut().expect("session hasn't been initialized");

    let tx = COMMAND_STREAM_TX.lock().await;
    let tx = tx.as_ref().expect("session hasn't been initialized");

    tx.send(Message::Text(request))
        .await
        .context("failed to send data to the command stream")?;

    let response = rx
        .recv()
        .await
        .context("failed to read from command stream")?;

    let mut response = response.to_string();

    let response: serde_json::Value =
        serde_json::from_str(&mut response).context("failed to deserialize the return data")?;

    if let Some(error) = response.get("error") {
        Err(anyhow::anyhow!(
            "{}",
            error.as_str().unwrap_or("N/A").to_string()
        ))
    } else {
        let response: Output =
            serde_json::from_value(response).context("failed to deserialize the return data")?;

        Ok(response)
    }
}

async fn command_loop(arguments: cmdline::Arguments) -> anyhow::Result<()> {
    let mut command_input_object =
        term::CommandInput::new().map_err(|e| anyhow::anyhow!("{}", e.to_string()))?;

    let username = arguments
        .username
        .clone()
        .context("uername is not specified")?;

    let server_name = login(
        &username,
        &arguments
            .password
            .clone()
            .context("password is not specified")?,
    )
    .await?;

    loop {
        if let Err(e) = commands_handle(&mut command_input_object, &server_name, &username).await {
            errorln!("{}", e.to_string());
        }
    }
}

pub async fn handle(arguments: cmdline::Arguments) -> anyhow::Result<()> {
    let (remote_address, remote_port) = arguments
        .remote_address
        .clone()
        .context("arguments.remote_address is None")?;

    outputln!("connecting to {}:{}", remote_address, remote_port);

    let (stream, response) = if arguments.tls {
        let url = format!("wss://{}:{}", remote_address, remote_port);

        let tls_config = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(arguments.disabled_tls_verification)
            .build()
            .context("failed to create a TLS config")?;

        let tls_connector = tokio_tungstenite::Connector::NativeTls(tls_config);

        tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(tls_connector))
            .await
            .context("failed to connect")?
    } else {
        let url = format!("ws://{}:{}", remote_address, remote_port);

        tokio_tungstenite::connect_async(url)
            .await
            .context("failed to connect")?
    };

    let response_status = response.status();

    if response_status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow::anyhow!(
            "server responded with status code {}",
            response_status.to_string()
        ));
    }

    let (mut write, mut read) = stream.split();

    outputln!("connected");

    let (command_in_tx, mut command_in_rx) = tokio::sync::mpsc::channel::<Message>(1);
    let (command_out_tx, command_out_rx) = tokio::sync::mpsc::channel::<Message>(1);

    {
        let mut stream_tx = COMMAND_STREAM_TX.lock().await;

        *stream_tx = Some(command_in_tx);
    }

    {
        let mut stream_rx = COMMAND_STREAM_RX.lock().await;

        *stream_rx = Some(command_out_rx);
    }

    tokio::spawn(async move {
        if let Err(e) = command_loop(arguments).await {
            errorln!("{}", e.to_string());
            std::process::exit(0);
        }
    });

    loop {
        tokio::select! {
            command = command_in_rx.recv() => {
                if let Some(command) = command {
                    write.send(command).await.context("failed to send data")?;
                }
            },
            data = read.next() => {
                if let Some(data) = data {
                    match data {
                        Ok(data) => {
                            if !matches!(data, Message::Ping(_)) {
                                command_out_tx.send(data).await.context("failed to push data to command stream")?
                            }
                        },
                        Err(_) => {
                            outputln!("stream closed");
                            std::process::exit(0);
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("stream closed"));
                }
            }
        }
    }
}
