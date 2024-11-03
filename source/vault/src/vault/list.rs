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

use crate::{access_keys, app_error::AppError, db, log, permission, vault};

#[actix_web::get("/{vault}")]
pub async fn req_list(
    ns: actix_web::web::Path<String>,
    req: actix_web::HttpRequest,
) -> impl actix_web::Responder {
    #[derive(serde::Serialize)]
    struct RequestResponseEntry {
        created: String,
        secret_name: String,
    }

    #[derive(serde::Serialize)]
    struct RequestResponse {
        vault: String,
        secrets: Vec<RequestResponseEntry>,
    }

    let mut ip = "N/A".to_owned();

    match vault::initialize_request(&req, permission::VaultRoles::ListSecrets, &ns, &mut ip) {
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

    let secrets_list = match db::secret::list(&ns) {
        Ok(value) => value,
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to list secrets",
                "msg": "failed to retrive secrets from the db",
                "err": e,
                "tags": [
                    "vault", "db", "error"
                ],
                "attr": {
                    "ip": ip,
                    "vault": ns.to_string(),
                }
            });

            return actix_web::HttpResponse::InternalServerError().finish();
        }
    };

    match simd_json::to_string(&RequestResponse {
        vault: ns.to_string(),
        secrets: secrets_list
            .iter()
            .map(|v| RequestResponseEntry {
                created: v.created.clone(),
                secret_name: v.secret_name.clone(),
            })
            .collect(),
    }) {
        Ok(response) => actix_web::HttpResponse::Ok()
            .content_type("application/json")
            .body(response),
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to list secrets",
                "msg": "failed to serialize the response",
                "err": AppError {
                    message: "serializing data".to_owned(),
                    error: Some(e.to_string()),
                    attr: None
                },
                "tags": [
                    "vault", "error"
                ],
                "attr": {
                    "ip": ip,
                    "vault": ns.to_string(),
                }
            });

            actix_web::HttpResponse::InternalServerError().finish()
        }
    }
}
