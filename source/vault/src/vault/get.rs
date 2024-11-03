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

use crate::{access_keys, app_error::AppError, db, log, permission, secrets, vault};

#[actix_web::get("/{vault}/{secret_name}")]
pub async fn req_get(
    path: actix_web::web::Path<(String, String)>,
    req: actix_web::HttpRequest,
) -> impl actix_web::Responder {
    let ns = path.0.clone();
    let secret_name = path.1.clone();
    let mut ip = "N/A".to_owned();

    match vault::initialize_request(&req, permission::VaultRoles::DecryptSecrets, &ns, &mut ip) {
        Some(vault::CommonAccessResult::Authorized) => {}
        Some(vault::CommonAccessResult::Unauthorized) => {
            access_keys::delay().await;
            return actix_web::HttpResponse::Unauthorized().finish();
        }
        None => {
            access_keys::delay().await;
            return actix_web::HttpResponse::InternalServerError().finish();
        }
    };

    let secret_document = match db::secret::find(&ns, &secret_name) {
        Ok(Some(value)) => value,
        Ok(None) => return actix_web::HttpResponse::NotFound().finish(),
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to retrieve secrets",
                "msg": "failed to retrive secret from the DB",
                "err": e,
                "tags": [
                    "vault", "request", "db", "error"
                ],
                "attr": {
                    "ip": ip,
                    "ns": ns,
                    "secret": secret_name
                }
            });

            return actix_web::HttpResponse::InternalServerError().finish();
        }
    };

    match base64_simd::STANDARD.decode_to_vec(secret_document.secret) {
        Ok(secret) => match secrets::decrypt(&secret) {
            Ok(value) => {
                log!({
                    "mod": log::Module::Vault,
                    "ctx": "request to retrieve secrets",
                    "msg": "secret retrieved",
                    "tags": [
                        "vault", "request",
                    ],
                    "attr": {
                        "ip": ip,
                        "ns": ns,
                        "secret": secret_name
                    }
                });

                actix_web::HttpResponse::Ok().body(value)
            }
            Err(e) => {
                log!({
                    "mod": log::Module::Vault,
                    "ctx": "request to retrieve secrets",
                    "msg": "failed to decrypt a secret",
                    "err": e,
                    "tags": [
                        "vault", "request", "error"
                    ],
                    "attr": {
                        "ip": ip,
                        "ns": ns,
                        "secret": secret_name
                    }
                });

                actix_web::HttpResponse::InternalServerError().finish()
            }
        },
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to retrieve secrets",
                "msg": "failed to decode a secret",
                "err": AppError {
                    message: "invalid base64 encoding".to_owned(),
                    error: Some(e.to_string()),
                    attr: None
                },
                "tags": [
                    "vault", "request", "error"
                ],
                "attr": {
                    "ip": ip,
                    "secret": ns,
                    "vault": secret_name
                }
            });

            actix_web::HttpResponse::InternalServerError().finish()
        }
    }
}
