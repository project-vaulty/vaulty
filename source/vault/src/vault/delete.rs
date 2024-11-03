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

use crate::{access_keys, db, log, permission, vault};

#[actix_web::delete("/{vault}/{secret_name}")]
pub async fn req_delete(
    path: actix_web::web::Path<(String, String)>,
    req: actix_web::HttpRequest,
) -> impl actix_web::Responder {
    let ns = path.0.clone();
    let secret_name = path.1.clone();
    let mut ip = "N/A".to_owned();

    match vault::initialize_request(&req, permission::VaultRoles::DeleteSecrets, &ns, &mut ip) {
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

    match db::secret::delete(&ns, &secret_name) {
        Ok(db::secret::DeleteSecretResult::Deleted) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to delete secrets",
                "msg": "secret deleted",
                "tags": [
                    "vault", "request"
                ],
                "attr": {
                    "ip": ip,
                    "ns": ns,
                    "secret": secret_name
                }
            });

            actix_web::HttpResponse::Ok().finish()
        }
        Ok(db::secret::DeleteSecretResult::NotFound) => {
            actix_web::HttpResponse::NotFound().finish()
        }
        Err(e) => {
            log!({
                "mod": log::Module::Vault,
                "ctx": "request to delete secrets",
                "msg": "failed to delete a secret",
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
