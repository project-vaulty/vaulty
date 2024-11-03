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

use rand::Rng;

pub mod access_keys;
pub mod api;
pub mod app_error;
pub mod cmd;
pub mod config;
pub mod db;
pub mod exit;
pub mod log;
pub mod permission;
pub mod secrets;
pub mod server;
pub mod user;
pub mod vault;

fn initialize_config() {
    let mut config_filename: Option<String> = None;
    let mut args = std::env::args().into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                if let Some(filename) = args.next() {
                    config_filename = Some(filename);
                }
            }
            _ => {}
        }
    }

    if let Err(e) = config::initialize(config_filename) {
        log!({
            mod: log::Module::Cfg,
            ctx: "initializing",
            msg: "failed to initialize the config module",
            err: e,
            tags: [
                "init", "config", "error"
            ],
        });

        exit::CONFIG.exit();
    }
}

fn initialize_log() {
    if let Err(e) = log::initialize() {
        log!({
            mod: log::Module::Log,
            ctx: "initializing",
            msg: "failed to initialize the log module",
            err: e,
            tags: [
                "init", "log", "error"
            ],
        });

        exit::LOG.exit();
    }
}

fn initialize_db() {
    match db::initialize() {
        Ok(init_state) => {
            if matches!(init_state, db::InitializeState::Created) {
                const ALLOWED_CHARS: &str =
                    "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
                const INITIAL_PASSWORD_LEN: usize = 20;
                const INITIAL_USERNAME: &str = "root";
                const INITIAL_SECURITY_GROUP: &str = "127.0.0.1/32";

                let mut random = rand::thread_rng();
                let mut initial_password = String::new();

                for _ in 0..INITIAL_PASSWORD_LEN {
                    initial_password.push(
                        ALLOWED_CHARS
                            .chars()
                            .nth(random.gen::<usize>() % ALLOWED_CHARS.len())
                            .unwrap(),
                    );
                }

                match user::create_user(
                    INITIAL_USERNAME,
                    &initial_password,
                    &permission::UserRole::Admin,
                    vec![INITIAL_SECURITY_GROUP.to_string()],
                ) {
                    Ok(db::user::InsertUserResult::Created) => {
                        log!({
                            mod: log::Module::Db,
                            ctx: "initializing",
                            msg: "root user created",
                            tags: [
                                "init", "db"
                            ],
                            attr: {
                                user: INITIAL_USERNAME,
                                password: initial_password,
                                sg: INITIAL_SECURITY_GROUP
                            }
                        });
                    }
                    Ok(db::user::InsertUserResult::Exists) => {}
                    Err(e) => {
                        log!({
                            mod: log::Module::Db,
                            ctx: "initializing",
                            msg: "failed to initialize the DB module",
                            err: e,
                            tags: [
                                "init", "db", "error"
                            ],
                        });

                        exit::DB.exit();
                    }
                }
            }
        }
        Err(e) => {
            log!({
                mod: log::Module::Db,
                ctx: "initializing",
                msg: "failed to initialize the DB module",
                err: e,
                tags: [
                    "init", "db", "error"
                ],
            });

            exit::DB.exit();
        }
    }
}

fn initialize_secrets() {
    if let Err(e) = secrets::initialize() {
        log!({
            mod: log::Module::Secrets,
            ctx: "initializing",
            msg: "failed to initialize the secrets module",
            err: e,
            tags: [
                "init", "secrets", "error"
            ],
        });

        exit::SECRETS.exit();
    }
}

fn initialize_access_keys() {
    if let Err(e) = access_keys::initialize() {
        log!({
            mod: log::Module::AccessKey,
            ctx: "initializing",
            msg: "failed to initialize the access key module",
            err: e,
            tags: [
                "init", "access_key", "error"
            ],
        });

        exit::IAM.exit();
    }
}

fn initialize_users() {
    user::initialize();
}

#[tokio::main]
async fn main() {
    println!("Copyright (C) 2024  S. Ivanov\n");

    initialize_config();
    initialize_log();
    initialize_db();
    initialize_secrets();
    initialize_access_keys();
    initialize_users();

    if let Err(e) = server::start().await {
        log!({
            mod: log::Module::Server,
            ctx: "initializing",
            msg: "failed to initialize the server module",
            err: e,
            tags: [
                "init", "server", "error"
            ],
        });

        exit::SERVER.exit();
    }
}
