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

use std::io::Read;

use maplit::hashmap;
use p256::ecdsa::signature::{Signer, Verifier};
use rand::Rng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

use crate::{
    app_error::{AppError, AppErrorResult, AppResult},
    config, db, permission,
};

static mut ECDSA_SIGNING_KEY: Option<p256::ecdsa::SigningKey> = None;
static mut ECDSA_VERIFYING_KEY: Option<p256::ecdsa::VerifyingKey> = None;
static mut DELAY_ON_UNSUCCESS: Option<u64> = None;

pub async fn delay() {
    let ms = unsafe { DELAY_ON_UNSUCCESS.expect("module IAM is not initialized") };

    tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
}

fn load_pem(filename: &str) -> AppResult<String> {
    let mut result = String::new();

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .append(false)
        .open(filename)
        .map_app_err(|e| AppError {
            message: "failed to open for reading".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned()
            }),
        })?;

    file.read_to_string(&mut result).map_app_err(|e| AppError {
        message: "failed to read".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename.to_owned()
        }),
    })?;

    Ok(result)
}

fn initialize_verifying_key() -> AppResult<()> {
    let config_clone = config::get_clone();
    let filename = config_clone.access_keys.verifying_key;
    let file_content = load_pem(&filename)?;

    let result =
        p256::ecdsa::VerifyingKey::from_public_key_pem(&file_content).map_app_err(|e| {
            AppError {
                message: "failed to load public key".to_owned(),
                error: Some(e.to_string()),
                attr: Some(hashmap! {
                    "filename".to_owned() => filename.to_owned()
                }),
            }
        })?;

    unsafe {
        ECDSA_VERIFYING_KEY = Some(result);
    }

    Ok(())
}

fn initialize_signing_key() -> AppResult<()> {
    let config_clone = config::get_clone();
    let filename = config_clone.access_keys.signing_key;
    let file_content = load_pem(&filename)?;

    let result =
        p256::ecdsa::SigningKey::from_pkcs8_pem(&file_content).map_app_err(|e| AppError {
            message: "failed to load private key".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned()
            }),
        })?;

    unsafe {
        ECDSA_SIGNING_KEY = Some(result);
    }

    Ok(())
}

pub fn initialize() -> AppResult<()> {
    let config_clone = config::get_clone();

    initialize_verifying_key()?;
    initialize_signing_key()?;

    unsafe {
        DELAY_ON_UNSUCCESS = Some(config_clone.access_keys.delay_unsuccessful_attempts_millis);
    }

    Ok(())
}

pub fn verify_access_key(key: &str, signature: &[u8]) -> AppResult<bool> {
    let verifying_key = unsafe { ECDSA_VERIFYING_KEY.clone().unwrap() };

    let signature: p256::ecdsa::Signature = p256::ecdsa::Signature::from_der(signature)
        .map_app_err(|e| AppError {
            message: "invalid signature".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "signature".to_owned() => base64_simd::STANDARD.encode_to_string(signature)
            }),
        })?;

    Ok(verifying_key.verify(key.as_bytes(), &signature).is_ok())
}

fn sign_secret(secret: &str) -> String {
    let siging_key = unsafe { ECDSA_SIGNING_KEY.clone().unwrap() };
    let signature: p256::ecdsa::Signature = siging_key.sign(secret.as_bytes());
    let signature = signature.to_der().to_bytes();

    base64_simd::STANDARD.encode_to_string(&signature)
}

pub struct CreateAccessKeyResult {
    pub access_key: String,
    pub secret_access_key: String,
}

pub fn create(
    vault: &str,
    sg: Vec<String>,
    permission: Vec<permission::VaultRoles>,
) -> AppResult<CreateAccessKeyResult> {
    const ALLOWED_CHARS: &str = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";

    let config_clone = config::get_clone();

    let mut random = rand::thread_rng();
    let mut access_key = String::new();
    let mut secret_access_key = String::new();

    loop {
        for _ in 0..config_clone.access_keys.acces_key_length {
            access_key.push(
                ALLOWED_CHARS
                    .chars()
                    .nth(random.gen::<usize>() % ALLOWED_CHARS.len())
                    .unwrap(),
            );
        }

        if db::access::find(vault, &access_key)?.is_some() {
            access_key = String::new();

            continue;
        } else {
            break;
        }
    }

    for _ in 0..config_clone.access_keys.secret_access_key_length {
        secret_access_key.push(
            ALLOWED_CHARS
                .chars()
                .nth(random.gen::<usize>() % ALLOWED_CHARS.len())
                .unwrap(),
        );
    }

    let mut parsed_sg = Vec::new();

    for v in sg {
        if let Some((network, ip)) = v.split_once('/') {
            let value = db::access::AccessKeySgDocument {
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

    let time_now = chrono::Utc::now();

    db::access::insert(
        vault,
        &access_key,
        db::access::AccessKeyDocument {
            secret_access_key: sign_secret(&secret_access_key),
            permission,
            sg: parsed_sg,
            created: time_now.to_rfc3339(),
            last_used: None,
        },
    )?;

    Ok(CreateAccessKeyResult {
        access_key,
        secret_access_key,
    })
}

pub fn delete_access_key(
    vault: &str,
    access_key: &str,
) -> AppResult<db::access::DeleteAccessKeyResult> {
    Ok(db::access::delete(vault, access_key)?)
}

pub enum ChangePermissionForAccessKeyResult {
    Updated,
    NotFound,
}

pub fn change_permission(
    vault: &str,
    access_key: &str,
    permission: Vec<permission::VaultRoles>,
) -> AppResult<ChangePermissionForAccessKeyResult> {
    match db::access::change_permission(vault, access_key, permission)? {
        db::access::ChangePermissionForAccessKeyResult::Updated => {
            Ok(ChangePermissionForAccessKeyResult::Updated)
        }
        db::access::ChangePermissionForAccessKeyResult::NotFound => {
            Ok(ChangePermissionForAccessKeyResult::NotFound)
        }
    }
}

pub enum ChangeSgForAccessKeyResult {
    Updated,
    NotFound,
}

pub fn change_sg(
    vault: &str,
    access_key: &str,
    sg: Vec<String>,
) -> AppResult<ChangeSgForAccessKeyResult> {
    let mut parsed_sg = Vec::new();

    for v in sg {
        if let Some((network, ip)) = v.split_once('/') {
            let value = db::access::AccessKeySgDocument {
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

    match db::access::change_sg(vault, access_key, parsed_sg)? {
        db::access::ChangeSgForAccessKeyResult::Updated => Ok(ChangeSgForAccessKeyResult::Updated),
        db::access::ChangeSgForAccessKeyResult::NotFound => {
            Ok(ChangeSgForAccessKeyResult::NotFound)
        }
    }
}
