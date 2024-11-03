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
    app_error::{AppError, AppErrorOption, AppResult},
    cmd, db, log, permission, user,
};

#[derive(Debug, Clone, serde::Serialize)]
enum ResponseState {
    Created,
    Exists,
    Denied,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    result: ResponseState,
}

pub async fn insert(session: &mut api::Session, data: cmd::RequestCreateUser) -> AppResult<()> {
    let executer_username = session
        .username
        .clone()
        .expect("state is command while user hasn't logged in");

    let executer = db::user::find(&executer_username)?.context_app_err(|| AppError {
        message: "command executing user is not in the DB".to_owned(),
        error: None,
        attr: None,
    })?;

    if matches!(executer.role, permission::UserRole::Admin) {
        match user::create_user(&data.username, &data.password, &data.role, data.sg)? {
            db::user::InsertUserResult::Created => {
                log!({
                    mod: log::Module::Vault,
                    ctx: "request to insert a secret",
                    msg: "user inserted",
                    tags: [
                        "api", "user", "request", "error"
                    ],
                    attr: {
                        ip: session.friendly_ip.clone(),
                        user: executer_username.clone(),
                        target_user: data.username
                    }
                });

                session
                    .send_response(&Response {
                        result: ResponseState::Created,
                    })
                    .await?;
            }
            db::user::InsertUserResult::Exists => {
                log!({
                    mod: log::Module::Vault,
                    ctx: "request to insert a secret",
                    msg: "user already exists",
                    tags: [
                        "api", "user", "request", "error"
                    ],
                    attr: {
                        ip: session.friendly_ip.clone(),
                        user: executer_username.clone(),
                        target_user: data.username
                    }
                });

                session
                    .send_response(&Response {
                        result: ResponseState::Exists,
                    })
                    .await?;
            }
        }
    } else {
        log!({
            mod: log::Module::Vault,
            ctx: "request to insert a user",
            msg: "insufficient permission",
            tags: [
                "api", "user", "request", "error"
            ],
            attr: {
                ip: session.friendly_ip.clone(),
                user: executer_username.clone(),
                target_user: data.username
            }
        });

        session
            .send_response(&Response {
                result: ResponseState::Denied,
            })
            .await?;
    }

    Ok(())
}
