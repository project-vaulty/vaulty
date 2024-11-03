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
    cmd, db, log, permission,
};

#[derive(Debug, Clone, serde::Serialize)]
enum ResponseResult {
    Deleted,
    NotFound,
    Denied,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Response {
    result: ResponseResult,
}

pub async fn delete(session: &mut api::Session, data: cmd::RequestDeleteUser) -> AppResult<()> {
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
        match db::user::delete(&data.username)? {
            db::user::DeleteUserResult::Deleted => {
                log!({
                    mod: log::Module::Vault,
                    ctx: "request to delete a user",
                    msg: "user deleted",
                    tags: [
                        "api", "user", "request"
                    ],
                    attr: {
                        ip: session.friendly_ip.clone(),
                        user: executer_username.clone(),
                        target_user: data.username
                    }
                });

                session
                    .send_response(&Response {
                        result: ResponseResult::Deleted,
                    })
                    .await?;
            }
            db::user::DeleteUserResult::NotFound => {
                log!({
                    mod: log::Module::Vault,
                    ctx: "request to delete a user",
                    msg: "user not found",
                    tags: [
                        "api", "user", "request"
                    ],
                    attr: {
                        ip: session.friendly_ip.clone(),
                        user: executer_username.clone(),
                        target_user: data.username
                    }
                });

                session
                    .send_response(&Response {
                        result: ResponseResult::NotFound,
                    })
                    .await?;
            }
        }
    } else {
        log!({
            mod: log::Module::Vault,
            ctx: "request to delete a user",
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
                result: ResponseResult::Denied,
            })
            .await?;
    }

    Ok(())
}
