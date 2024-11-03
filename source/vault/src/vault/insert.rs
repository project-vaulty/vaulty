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

use crate::{access_keys, db, log, permission, secrets, vault};

#[inline]
async fn insert_secret(
    path: actix_web::web::Path<(String, String)>,
    req: actix_web::HttpRequest,
    data: actix_web::web::Bytes,
) -> impl actix_web::Responder {
    let ns = path.0.clone();
    let secret_name = path.1.clone();
    let mut ip = "N/A".to_owned();

    match vault::initialize_request(&req, permission::VaultRoles::CreateSecrets, &ns, &mut ip) {
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

    if data.is_empty() {
        return actix_web::HttpResponse::UnprocessableEntity().finish();
    }

    let data = match secrets::encrypt(&data.to_vec()) {
        Ok(value) => value,
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to insert secrets",
                "msg": "failed to encrypt the secret",
                "err": e,
                "tags": [
                    "vault", "error"
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

    let time_now = chrono::Utc::now();

    let secret = db::secret::SecretDocument {
        created: time_now.to_rfc3339(),
        secret: base64_simd::STANDARD.encode_to_string(data),
    };

    match db::secret::insert(&ns, &secret_name, secret) {
        Ok(db::secret::InsertSecretResult::Inserted) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to insert secrets",
                "msg": "secret inserted",
                "tags": [
                    "vault", "db", "error"
                ],
                "attr": {
                    "ip": ip,
                    "status": "inserted",
                    "ns": ns,
                    "secret": secret_name
                }
            });

            actix_web::HttpResponse::Created().finish()
        }
        Ok(db::secret::InsertSecretResult::Updated) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to insert secrets",
                "msg": "secret inserted",
                "tags": [
                    "vault", "db", "error"
                ],
                "attr": {
                    "ip": ip,
                    "status": "updated",
                    "ns": ns,
                    "secret": secret_name
                }
            });

            actix_web::HttpResponse::Ok().finish()
        }
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to insert secrets",
                "msg": "failed to insertthe secret",
                "err": e,
                "tags": [
                    "vault", "db", "error"
                ],
                "attr": {
                    "ip": ip,
                    "ns": ns,
                    "secret": secret_name
                }
            });

            return actix_web::HttpResponse::InternalServerError().finish();
        }
    }
}

#[actix_web::post("/{vault}/{secret_name}")]
pub async fn req_post(
    path: actix_web::web::Path<(String, String)>,
    req: actix_web::HttpRequest,
    data: actix_web::web::Bytes,
) -> impl actix_web::Responder {
    insert_secret(path, req, data).await
}

#[actix_web::put("/{vault}/{secret_name}")]
pub async fn req_put(
    path: actix_web::web::Path<(String, String)>,
    req: actix_web::HttpRequest,
    data: actix_web::web::Bytes,
) -> impl actix_web::Responder {
    insert_secret(path, req, data).await
}
