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
    api,
    app_error::{AppError, AppErrorResult, AppResult},
    config, log, vault,
};

fn load_cert(filename: String) -> AppResult<Vec<rustls::Certificate>> {
    let mut result = Vec::new();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(&filename)
        .map_app_err(|e| AppError {
            message: "failed to open for reading".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })?;

    let reader = &mut std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(reader).map_app_err(|e| AppError {
        message: "failed to load the certificate".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename.to_owned(),
        }),
    })?;

    for cert in certs {
        result.push(rustls::Certificate(cert));
    }

    Ok(result)
}

fn load_key(filename: String) -> AppResult<rustls::PrivateKey> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(&filename)
        .map_app_err(|e| AppError {
            message: "failed to open for reading".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })?;

    let reader = &mut std::io::BufReader::new(file);
    let key = rustls_pemfile::pkcs8_private_keys(reader).map_app_err(|e| AppError {
        message: "failed to load the private key".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename.to_owned(),
        }),
    })?;

    if key.is_empty() {
        Err(AppError {
            message: "failed to load the private key".to_owned(),
            error: Some("missing key".to_owned()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })
    } else {
        Ok(rustls::PrivateKey(key[0].clone()))
    }
}

pub async fn start() -> AppResult<()> {
    let config_clone = config::get_clone();
    let friendly_listen_address = format!(
        "{}:{}",
        config_clone.server.listen_address, config_clone.server.listen_port
    );

    loop {
        let server = if let Some(tls) = &config_clone.server.tls {
            let tls_cert = load_cert(tls.certificate.clone())?;
            let tls_key = load_key(tls.key.clone())?;

            let server_tls_config = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(tls_cert, tls_key)
                .map_app_err(|e| AppError {
                    message: "failed to build the TLS config".to_owned(),
                    error: Some(e.to_string()),
                    attr: None,
                })?;

            actix_web::HttpServer::new(|| {
                actix_web::App::new()
                    .service(api::web_socket)
                    .service(vault::req_list)
                    .service(vault::req_get)
                    .service(vault::req_post)
                    .service(vault::req_put)
                    .service(vault::req_delete)
            })
            .keep_alive(actix_web::http::KeepAlive::Disabled)
            .backlog(u32::MAX)
            .bind_rustls(
                (
                    config_clone.server.listen_address.clone(),
                    config_clone.server.listen_port,
                ),
                server_tls_config,
            )
            .map_app_err(|e| AppError {
                message: "failed to run the HTTP server".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "bind_address".to_owned() => friendly_listen_address.clone(),
                }),
            })?
            .run()
        } else {
            actix_web::HttpServer::new(|| {
                actix_web::App::new()
                    .service(api::web_socket)
                    .service(vault::req_list)
                    .service(vault::req_get)
                    .service(vault::req_post)
                    .service(vault::req_put)
                    .service(vault::req_delete)
            })
            .keep_alive(actix_web::http::KeepAlive::Disabled)
            .backlog(u32::MAX)
            .bind((
                config_clone.server.listen_address.clone(),
                config_clone.server.listen_port,
            ))
            .map_app_err(|e| AppError {
                message: "failed to run the HTTP server".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "bind_address".to_owned() => friendly_listen_address.clone(),
                }),
            })?
            .run()
        };

        log!({
            mod: log::Module::Server,
            ctx: "server initializing",
            msg: "starting the server",
            tags: [
                "init", "db"
            ],
            attr: {
                bind_address: friendly_listen_address.clone()
            }
        });

        match server.await {
            Ok(()) => break,
            Err(e) => log!({
                mod: log::Module::Server,
                ctx: "server runtime",
                msg: "runtime error",
                err: AppError {
                    message: e.to_string(),
                    error: None,
                    attr: None
                },
                tags: [
                    "init", "db", "error"
                ],
                attr: {
                    bind_address: friendly_listen_address.clone()
                }
            }),
        }
    }

    log!({
        mod: log::Module::Server,
        ctx: "server runtime",
        msg: "stopping the server",
        tags: [
            "init", "db"
        ],
        attr: {
            bind_address: friendly_listen_address
        }
    });

    Ok(())
}
