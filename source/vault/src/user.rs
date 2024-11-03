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
    app_error::{AppError, AppErrorResult, AppResult},
    config, db, log, permission,
};

use argon2::{password_hash::PasswordHasher, PasswordVerifier};
use maplit::hashmap;

static mut DELAY_ON_UNSUCCESS: Option<u64> = None;

pub async fn delay() {
    let ms = unsafe { DELAY_ON_UNSUCCESS.expect("module IAM is not initialized") };

    tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
}

pub fn initialize() {
    let config_clone = config::get_clone();

    unsafe {
        DELAY_ON_UNSUCCESS = Some(config_clone.users.delay_unsuccessful_attempts_millis);
    }
}

fn hash_password(password: &str) -> AppResult<String> {
    let config = argon2::Argon2::default();
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

    Ok(config
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError {
            message: "failed to hash the password".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?
        .to_string())
}

pub enum VerifyPasswordResult {
    Authorized,
    Unathorized,
}

fn verify_password(password: &str, verifying_password: &str) -> AppResult<VerifyPasswordResult> {
    let config = argon2::Argon2::default();
    let verifying_password =
        argon2::PasswordHash::new(verifying_password).map_err(|e| AppError {
            message: "failed to serialize the verifying password".to_owned(),
            error: Some(e.to_string()),
            attr: None,
        })?;

    if config
        .verify_password(password.as_bytes(), &verifying_password)
        .is_ok()
    {
        Ok(VerifyPasswordResult::Authorized)
    } else {
        Ok(VerifyPasswordResult::Unathorized)
    }
}

pub enum LoginResult {
    Successful,
    Failed,
}

pub fn login(
    requester_ip: std::net::IpAddr,
    username: &str,
    password: &str,
) -> AppResult<LoginResult> {
    match db::user::find(&username)? {
        Some(user) => {
            let mut ip_in_sg = false;

            for sg in &user.sg {
                let network_prefix = sg.prefix;
                let network: std::net::IpAddr = sg.network.parse().map_app_err(|_| AppError {
                    message: "invalid network".to_owned(),
                    error: None,
                    attr: Some(hashmap! {
                        "user".to_owned() => username.to_owned(),
                    }),
                })?;

                if network_prefix > if network.is_ipv4() { 32 } else { 128 } {
                    return Err(AppError {
                        message: "invalid network prefix".to_owned(),
                        error: None,
                        attr: Some(hashmap! {
                            "user".to_owned() => username.to_owned(),
                            "network".to_owned() => sg.network.to_owned(),
                            "network_prefix".to_owned() => network_prefix.to_string()
                        }),
                    });
                }

                let network = ipnetwork::IpNetwork::new(network, (network_prefix & 0xFF) as u8)
                    .map_app_err(|e| AppError {
                        message: "invalid security group".to_owned(),
                        error: Some(e.to_string()),
                        attr: Some(hashmap! {
                            "user".to_owned() => username.to_owned(),
                            "ip".to_owned() => sg.network.to_owned(),
                            "network_prefix".to_owned() => network_prefix.to_string()
                        }),
                    })?;

                if network.contains(requester_ip) {
                    ip_in_sg = true;
                    break;
                }
            }

            if ip_in_sg {
                match verify_password(&password, &user.password)? {
                    VerifyPasswordResult::Authorized => {
                        if let Err(e) = db::user::refresh_last_active(username) {
                            log!({
                                mod: log::Module::User,
                                ctx: "refreshing the user's last login",
                                msg: "failed to update the DB",
                                err: e,
                                tags: [
                                    "user", "db", "error"
                                ],
                                attr: {
                                    user: username
                                }
                            });
                        }

                        Ok(LoginResult::Successful)
                    }
                    _ => Ok(LoginResult::Failed),
                }
            } else {
                Ok(LoginResult::Failed)
            }
        }
        None => Ok(LoginResult::Failed),
    }
}

pub fn create_user(
    username: &str,
    password: &str,
    role: &permission::UserRole,
    sg: Vec<String>,
) -> AppResult<db::user::InsertUserResult> {
    let mut parsed_sg = Vec::new();

    for v in sg {
        if let Some((network, ip)) = v.split_once('/') {
            let value = db::user::UserSgDocument {
                network: network.to_string(),
                prefix: ip.parse::<i32>().map_app_err(|_| AppError {
                    message: "invalid network prefix".to_owned(),
                    error: None,
                    attr: Some(hashmap! {
                        "sg".to_owned() => v.to_owned()
                    }),
                })?,
            };

            parsed_sg.push(value);
        } else {
            return Err(AppError {
                message: "invalid security group".to_owned(),
                error: None,
                attr: Some(hashmap! {
                    "sg".to_owned() => v.to_owned()
                }),
            });
        }
    }

    let password = hash_password(&password)?;

    db::user::insert(
        username,
        db::user::UserDocument {
            password: password,
            role: role.clone(),
            last_login: None,
            sg: parsed_sg,
        },
    )
}

pub fn change_password(
    username: &str,
    password: &str,
) -> AppResult<db::user::ChangeUserPasswordResult> {
    let password = hash_password(&password)?;

    db::user::change_password(username, &password)
}

pub fn change_sg(username: &str, sg: Vec<String>) -> AppResult<db::user::ChangeUserSgResult> {
    let mut parsed_sg = Vec::new();

    for v in sg {
        if let Some((network, ip)) = v.split_once('/') {
            let value = db::user::UserSgDocument {
                network: network.to_string(),
                prefix: ip.parse::<i32>().map_app_err(|_| AppError {
                    message: "invalid network prefix".to_owned(),
                    error: None,
                    attr: Some(hashmap! {
                        "sg".to_owned() => v.to_owned()
                    }),
                })?,
            };

            parsed_sg.push(value);
        } else {
            return Err(AppError {
                message: "invalid security group".to_owned(),
                error: None,
                attr: Some(hashmap! {
                    "sg".to_owned() => v.to_owned()
                }),
            });
        }
    }

    db::user::change_sg(username, parsed_sg)
}
