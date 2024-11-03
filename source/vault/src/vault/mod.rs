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
    access_keys,
    app_error::{AppError, AppErrorOption, AppErrorResult, AppResult},
    db, log, permission,
};

mod delete;
mod get;
mod insert;
mod list;

pub use delete::req_delete;
pub use get::req_get;
pub use insert::req_post;
pub use insert::req_put;
pub use list::req_list;

pub enum CommonAccessResult {
    Authorized,
    Unauthorized,
}

#[inline]
fn access_check(
    requester_ip: std::net::IpAddr,
    access_key: &String,
    secret_access_key: &String,
    permission: permission::VaultRoles,
    vault: &str,
) -> AppResult<CommonAccessResult> {
    if let Some(ac_document) = db::access::find(vault, &access_key)? {
        let mut ip_in_sg = false;

        for sg in &ac_document.sg {
            let network_prefix = sg.prefix;
            let network: std::net::IpAddr = sg.network.parse().map_app_err(|_| AppError {
                message: "invalid network".to_owned(),
                error: None,
                attr: Some(hashmap! {
                    "access_key".to_owned() => access_key.clone(),
                    "vault".to_owned() => vault.to_owned(),
                    "ip".to_owned() => sg.network.to_owned()
                }),
            })?;

            if network_prefix > if network.is_ipv4() { 32 } else { 128 } {
                return Err(AppError {
                    message: "invalid network prefix".to_owned(),
                    error: None,
                    attr: Some(hashmap! {
                        "access_key".to_owned() => access_key.clone(),
                        "vault".to_owned() => vault.to_owned(),
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
                        "access_key".to_owned() => access_key.clone(),
                        "vault".to_owned() => vault.to_owned(),
                        "ip".to_owned() => sg.network.to_owned(),
                        "network_prefix".to_owned() => network_prefix.to_string()
                    }),
                })?;

            if network.contains(requester_ip) {
                ip_in_sg = true;
                break;
            }
        }

        if !ip_in_sg {
            return Ok(CommonAccessResult::Unauthorized);
        }

        let document_secret_access_key = base64_simd::STANDARD
            .decode_to_vec(&ac_document.secret_access_key)
            .map_app_err(|e| AppError {
                message: "failed to decode the secret access key".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "access_key".to_owned() => access_key.clone(),
                    "vault".to_owned() => vault.to_owned()
                }),
            })?;

        if access_keys::verify_access_key(&secret_access_key, &document_secret_access_key)? {
            if ac_document.permission.contains(&permission) {
                return Ok(CommonAccessResult::Authorized);
            }
        } else {
            return Ok(CommonAccessResult::Unauthorized);
        }
    }

    Ok(CommonAccessResult::Unauthorized)
}

#[inline]
fn process_host_ip(host: Option<&str>) -> AppResult<std::net::IpAddr> {
    let host = host.context_app_err(|| AppError {
        message: "missing IP from the request".to_owned(),
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

#[inline]
fn process_sig(req: &actix_web::HttpRequest) -> Option<(String, String)> {
    if let Some(authorization) = req.headers().get("Authorization") {
        if let Ok(authorization) = authorization.to_str() {
            const MAGIC_AUTHORIZATION_WORD: &str = "VAULTY";

            if authorization.len() >= MAGIC_AUTHORIZATION_WORD.len()
                && authorization[0..MAGIC_AUTHORIZATION_WORD.len()]
                    .to_uppercase()
                    .starts_with(MAGIC_AUTHORIZATION_WORD)
            {
                let sig = authorization[MAGIC_AUTHORIZATION_WORD.len()..].trim();

                if let Some((access_key, secret_access_key)) = sig.split_once(':') {
                    return Some((access_key.to_owned(), secret_access_key.to_owned()));
                }
            }
        }
    }

    None
}

#[inline]
fn initialize_request(
    req: &actix_web::HttpRequest,
    request_permission: permission::VaultRoles,
    vault: &str,
    requester_ip: &mut String,
) -> Option<CommonAccessResult> {
    let ip = match process_host_ip(req.connection_info().realip_remote_addr()) {
        Ok(value) => value,
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "initial request processing",
                "msg": "failed to retrive requester's IP",
                "err": e,
                "tags": [
                    "vault", "access", "error"
                ],
            });

            return None;
        }
    };

    *requester_ip = ip.to_string();

    let (access_key, secret_access_key) =
        if let Some((access_key, secret_access_key)) = process_sig(&req) {
            (access_key, secret_access_key)
        } else {
            log!({
                "mod": log::Module::Vault,
                "ctx": "initial request processing",
                "msg": "access was denied",
                "err": AppError {
                    message: "invalid authrorize headers".to_owned(),
                    error: None,
                    attr: None
                },
                "tags": [
                    "vault", "access", "denied"
                ],
                "attr": {
                    "ip": ip.to_string()
                }
            });

            return Some(CommonAccessResult::Unauthorized);
        };

    match access_check(
        ip,
        &access_key,
        &secret_access_key,
        request_permission,
        vault,
    ) {
        Ok(CommonAccessResult::Authorized) => {
            if let Err(e) = db::access::refresh_access_time(vault, &access_key) {
                log!({
                    "mod": log::Module::Vault,
                    "ctx": "refereshing access key's last use",
                    "msg": "failed to referesh",
                    "err": e,
                    "tags": [
                        "vault", "access", "error"
                    ],
                    "attr": {
                        "ip": ip.to_string()
                    }
                });
            }

            Some(CommonAccessResult::Authorized)
        }
        Ok(CommonAccessResult::Unauthorized) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "initial request processing",
                "msg": "access was denied",
                "err": AppError {
                    message: "ip is not in the security group or invalid secret access key".to_owned(),
                    error: None,
                    attr: None
                },
                "tags": [
                    "vault", "access", "denied"
                ],
                "attr": {
                    "ip": ip.to_string()
                }
            });

            Some(CommonAccessResult::Unauthorized)
        }
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "initial request processing",
                "msg": "failed to check the access",
                "err": e,
                "tags": [
                    "vault", "access", "error"
                ],
                "attr": {
                    "ip": ip.to_string()
                }
            });

            None
        }
    }
}
