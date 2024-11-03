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

use futures::StreamExt;
use maplit::hashmap;

use crate::{
    app_error::{AppError, AppErrorOption, AppErrorResult, AppResult},
    cmd, config, log, user,
};

const MAXIMUM_FRAME_SIZE: usize = 128 * 1042 * 1024;

pub enum SessionState {
    Login,
    Command,
}

pub struct Session {
    pub friendly_ip: String,
    pub ip: std::net::IpAddr,
    pub state: SessionState,
    pub username: Option<String>,
    pub ws_session: Option<actix_ws::Session>,
    pub lock: tokio::sync::Mutex<()>,
}

impl Session {
    fn new(ip: &std::net::IpAddr, ws_session: actix_ws::Session) -> Session {
        Session {
            ip: ip.clone(),
            friendly_ip: ip.to_string(),
            state: SessionState::Login,
            username: None,
            ws_session: Some(ws_session),
            lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn close(&mut self) {
        let stream = self
            .ws_session
            .take()
            .expect("close was used before Session was initialized");

        let close_reason = actix_ws::CloseReason::from(actix_ws::CloseCode::Error);

        let _ = stream.close(Some(close_reason)).await;
    }

    pub async fn pong(&mut self, data: &[u8]) {
        let stream = self
            .ws_session
            .as_mut()
            .expect("send_response was used before Session was initialized");

        let _ = self.lock.lock().await;
        let _ = stream.pong(data).await;
    }

    async fn ping(&mut self) -> AppResult<()> {
        let ping_data: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let stream = self
            .ws_session
            .as_mut()
            .expect("send_response was used before Session was initialized");

        let _ = self.lock.lock().await;

        Ok(stream.ping(&ping_data).await.map_app_err(|e| AppError {
            message: "failed to ping".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?)
    }

    pub async fn send_response<T>(&mut self, data: T) -> AppResult<()>
    where
        T: serde::Serialize,
    {
        let state = match self.state {
            SessionState::Login => "login",
            SessionState::Command => "command",
        };

        let stream = self
            .ws_session
            .as_mut()
            .expect("send_response was used before Session was initialized");

        let response = simd_json::to_string(&data).map_app_err(|e| AppError {
            message: "failed to serialize the responsee".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap![
                "state".to_owned() => state.to_owned(),
                "ip".to_owned() => self.friendly_ip.clone()
            ]),
        })?;

        let _ = self.lock.lock().await;
        let _ = stream.text(response).await.map_app_err(|_| AppError {
            message: "failed send the response".to_owned(),
            error: Some("stream was closed".to_owned()),
            attr: Some(hashmap![
                "state".to_owned() => state.to_owned(),
                "ip".to_owned() => self.friendly_ip.clone()
            ]),
        })?;

        Ok(())
    }

    async fn login_handle(&mut self, data: &str) -> AppResult<user::LoginResult> {
        #[derive(Debug, Clone, serde::Deserialize)]
        struct Request {
            username: String,
            password: String,
        }

        #[derive(Debug, Clone, serde::Serialize)]
        enum ResponseResult {
            Granted,
            Denied,
        }

        #[derive(Debug, Clone, serde::Serialize)]
        struct Response {
            result: ResponseResult,
            node_name: Option<String>,
        }

        let mut data = data.to_string();

        let request: Request =
            unsafe { simd_json::from_str(&mut data) }.map_app_err(|e| AppError {
                message: "invalid data received".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap![
                    "state".to_owned() => "login".to_owned(),
                    "ip".to_owned() => self.friendly_ip.clone()
                ]),
            })?;

        match user::login(self.ip, &request.username, &request.password)? {
            user::LoginResult::Successful => {
                log!({
                    mod: log::Module::Api,
                    ctx: "api login",
                    msg: "user successfully logged in",
                    tags: [
                        "api", "access", "login"
                    ],
                    attr: {
                        ip: self.friendly_ip.clone(),
                        user: request.username.clone(),
                    }
                });

                self.send_response(&Response {
                    result: ResponseResult::Granted,
                    node_name: Some(config::get_clone().node_name),
                })
                .await?;

                self.username = Some(request.username);
                self.state = SessionState::Command;

                Ok(user::LoginResult::Successful)
            }
            user::LoginResult::Failed => {
                log!({
                    mod: log::Module::Api,
                    ctx: "api login",
                    msg: "user provided invalid credentials",
                    tags: [
                        "api", "access", "login"
                    ],
                    attr: {
                        ip: self.friendly_ip.clone(),
                        user: request.username.clone(),
                    }
                });

                user::delay().await;

                self.send_response(&Response {
                    result: ResponseResult::Denied,
                    node_name: None,
                })
                .await?;

                Ok(user::LoginResult::Failed)
            }
        }
    }

    async fn step(&mut self, data: String, command: &mut String) -> AppResult<()> {
        /* simd_json corrupts the input data */
        let mut data = data.trim().to_string();

        let request: cmd::Request =
            unsafe { simd_json::from_str(&mut data) }.map_app_err(|e| AppError {
                message: "invalid data received".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap![
                    "state".to_owned() => "command".to_owned(),
                    "ip".to_owned() => self.friendly_ip.clone()
                ]),
            })?;

        *command = request.to_command_string();

        log!({
            mod: log::Module::Api,
            ctx: "websockets handle",
            msg: "executing a command",
            tags: [
                "api", "execution"
            ],
            attr: {
                ip: self.friendly_ip.clone(),
                user: self.username.clone(),
                command: command.clone()
            }
        });

        match request {
            cmd::Request::CreateUser(data) => cmd::user::insert(self, data).await?,
            cmd::Request::ListUsers() => cmd::user::list(self).await?,
            cmd::Request::FindUser(data) => cmd::user::find(self, data).await?,
            cmd::Request::DeleteUser(data) => cmd::user::delete(self, data).await?,
            cmd::Request::PromoteUser(data) => cmd::user::promote(self, data).await?,
            cmd::Request::DemoteUser(data) => cmd::user::demote(self, data).await?,
            cmd::Request::ChangePasswordForUser(data) => {
                cmd::user::change_password(self, data).await?
            }
            cmd::Request::ChangeSgForUser(data) => cmd::user::change_sg(self, data).await?,
            cmd::Request::CreateAccessKey(data) => cmd::access::insert(self, data).await?,
            cmd::Request::ListAccessKeys(data) => cmd::access::list(self, data).await?,
            cmd::Request::FindAccessKey(data) => cmd::access::find(self, data).await?,
            cmd::Request::DeleteAccessKey(data) => cmd::access::delete(self, data).await?,
            cmd::Request::ChangePermissionForAccessKey(data) => {
                cmd::access::change_permission(self, data).await?
            }
            cmd::Request::ChangeSgForAccessKey(data) => cmd::access::change_sg(self, data).await?,
            cmd::Request::ListVaults() => cmd::vault::list(self).await?,
            cmd::Request::FindVault(data) => cmd::vault::find(self, data).await?,
            cmd::Request::DeleteVault(data) => cmd::vault::delete(self, data).await?,
            cmd::Request::InsertSecret(data) => cmd::secret::insert(self, data).await?,
            cmd::Request::ListSecrets(data) => cmd::secret::list(self, data).await?,
            cmd::Request::FindSecret(data) => cmd::secret::find(self, data).await?,
            cmd::Request::DeleteSecret(data) => cmd::secret::delete(self, data).await?,
        }

        Ok(())
    }
}

#[inline]
fn process_host_ip(host: Option<&str>) -> AppResult<std::net::IpAddr> {
    let host = host.context_app_err(|| AppError {
        message: "missing IP in the request".to_owned(),
        error: None,
        attr: None,
    })?;

    if let Some((host, _port)) = host.split_once(':') {
        Ok(host.parse().map_app_err(|_| AppError {
            message: "invalid ip in the request".to_owned(),
            error: None,
            attr: Some(hashmap! {
                "ip".to_owned() => host.to_string(),
            }),
        })?)
    } else {
        Ok(host.parse().map_app_err(|_| AppError {
            message: "invalid ip in the request".to_owned(),
            error: None,
            attr: Some(hashmap! {
                "ip".to_owned() => host.to_string(),
            }),
        })?)
    }
}

#[actix_web::get("/")]
async fn web_socket(
    req: actix_web::HttpRequest,
    stream: actix_web::web::Payload,
) -> impl actix_web::Responder {
    let (ip, friendly_ip) = match process_host_ip(req.connection_info().realip_remote_addr()) {
        Ok(value) => (value, value.to_string()),
        Err(e) => {
            log!({
                mod: log::Module::Api,
                ctx: "websockets call",
                msg: "failed to get client's IP",
                err: e,
                tags: [
                    "api", "error"
                ]
            });

            return actix_web::HttpResponse::InternalServerError().finish();
        }
    };

    match actix_ws::handle(&req, stream).map_app_err(|e| AppError {
        message: "failed to begin handling websocket".to_owned(),
        error: Some(e.to_string()),
        attr: None,
    }) {
        Ok((res, ws_session, stream)) => {
            let mut user_session = Session::new(&ip, ws_session);

            let mut stream = stream
                .max_frame_size(MAXIMUM_FRAME_SIZE)
                .aggregate_continuations();

            actix_web::rt::spawn(async move {
                log!({
                    mod: log::Module::Api,
                    ctx: "websockets handle",
                    msg: "new connection",
                    tags: [
                        "api", "access"
                    ],
                    attr: {
                        ip: friendly_ip.clone()
                    }
                });

                let mut user_authorized = false;

                if let Some(msg) = stream.next().await {
                    match msg {
                        Ok(actix_ws::AggregatedMessage::Text(data)) => {
                            match user_session.login_handle(&data).await {
                                Ok(user::LoginResult::Successful) => user_authorized = true,
                                Ok(user::LoginResult::Failed) => user_authorized = false,
                                Err(e) => {
                                    log!({
                                        mod: log::Module::Api,
                                        ctx: "websockets handle",
                                        msg: "error occured while logging the user",
                                        err: e,
                                        tags: [
                                            "api", "error"
                                        ],
                                        attr: {
                                            ip: friendly_ip.clone()
                                        }
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if user_authorized {
                    let user_session = std::sync::Arc::new(tokio::sync::Mutex::new(user_session));
                    let stream_closing =
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

                    {
                        let user_session = user_session.clone();
                        let stream_closing = stream_closing.clone();
                        let friendly_ip = friendly_ip.clone();

                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                                let mut user_session = user_session.lock().await;

                                if let Err(e) = user_session.ping().await {
                                    log!({
                                        mod: log::Module::Api,
                                        ctx: "websockets handle",
                                        msg: "failed to ping the client",
                                        err: e,
                                        tags: [
                                            "api", "error"
                                        ],
                                        attr: {
                                            ip: friendly_ip.clone(),
                                            user: user_session.username.clone(),
                                        }
                                    });

                                    stream_closing
                                        .store(true, std::sync::atomic::Ordering::Relaxed);

                                    break;
                                }
                            }
                        });
                    }

                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

                    loop {
                        tokio::select! {
                            _ = async {
                                loop {
                                    if stream_closing.load(std::sync::atomic::Ordering::Relaxed) {
                                        break;
                                    }

                                    interval.tick().await;
                                }
                            } => {
                                let user_session = user_session.lock().await;

                                log!({
                                    mod: log::Module::Api,
                                    ctx: "websockets handle",
                                    msg: "stream was closed",
                                    tags: [
                                        "api", "error"
                                    ],
                                    attr: {
                                        ip: friendly_ip.clone(),
                                        user: user_session.username.clone()
                                    }
                                });

                                return;
                            }
                            msg = stream.next() => {
                                if let Some(msg) = msg {
                                    match msg {
                                        Ok(actix_ws::AggregatedMessage::Text(data)) => {
                                            let (username, command, step_result) = {
                                                let mut user_session = user_session.lock().await;
                                                let mut command = String::new();
                                                let result = user_session.step(data.to_string(), &mut command).await;

                                                (user_session.username.clone().expect("command executed without user being logged in"), command, result)
                                            };

                                            if let Err(e) = step_result {
                                                log!({
                                                    mod: log::Module::Api,
                                                    ctx: "websockets handle",
                                                    msg: "failed to handle client's message",
                                                    err: e.clone(),
                                                    tags: [
                                                        "api", "execution", "error"
                                                    ],
                                                    attr: {
                                                        ip: friendly_ip.clone(),
                                                        user: username,
                                                        command: command
                                                    }
                                                });

                                                #[derive(serde::Serialize)]
                                                struct Response {
                                                    error: String,
                                                }

                                                {
                                                    let mut user_session = user_session.lock().await;

                                                    if let Err(_) = user_session
                                                        .send_response(&Response {
                                                            error: e.message.clone(),
                                                        })
                                                        .await
                                                    {
                                                        user_session.close().await;
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            let user_session = user_session.lock().await;

                                            log!({
                                                mod: log::Module::Api,
                                                ctx: "websockets handle",
                                                msg: "failed to receive data",
                                                err: AppError {
                                                    message: e.to_string(),
                                                    error: None,
                                                    attr: None
                                                },
                                                tags: [
                                                    "api", "error"
                                                ],
                                                attr: {
                                                    ip: friendly_ip.clone(),
                                                    user: user_session.username.clone()
                                                }
                                            });

                                            return
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                } else {
                    let _ = &user_session.close().await;
                }
            });

            res
        }
        Err(e) => {
            log!({
                mod: log::Module::Api,
                ctx: "websockets handle",
                msg: "failed to handle a new connection",
                err: e,
                tags: [
                    "api", "error"
                ],
                attr: {
                    ip: friendly_ip
                }
            });

            actix_web::HttpResponse::InternalServerError().finish()
        }
    }
}
