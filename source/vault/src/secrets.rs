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

use aes_gcm::{aead::Aead, KeyInit};
use maplit::hashmap;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

use crate::{
    app_error::{AppError, AppErrorResult, AppResult},
    config,
};

static mut RSA_PRIVATE_KEY: Option<rsa::RsaPrivateKey> = None;
static mut RSA_PUBLIC_KEY: Option<rsa::RsaPublicKey> = None;
static mut AES_KEY: Option<Vec<u8>> = None;
static mut AES_IV: Option<Vec<u8>> = None;

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
                "filename".to_owned() => filename.to_owned(),
            }),
        })?;

    file.read_to_string(&mut result).map_app_err(|e| AppError {
        message: "failed to read".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename.to_owned(),
        }),
    })?;

    Ok(result)
}

fn load_rsa_private_key(filename: String) -> AppResult<()> {
    let file_content = load_pem(&filename)?;

    let result = rsa::RsaPrivateKey::from_pkcs8_pem(&file_content).map_app_err(|e| AppError {
        message: "failed to load the PEM".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename.to_owned(),
        }),
    })?;

    unsafe {
        RSA_PRIVATE_KEY = Some(result);
    }

    Ok(())
}

fn load_rsa_public_key(filename: String) -> AppResult<()> {
    let file_content = load_pem(&filename)?;

    let result =
        rsa::RsaPublicKey::from_public_key_pem(&file_content).map_app_err(|e| AppError {
            message: "failed to load the PEM".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })?;

    unsafe {
        RSA_PUBLIC_KEY = Some(result);
    }

    Ok(())
}

fn load_aes_key(filename: String) -> AppResult<()> {
    let file_content = load_pem(&filename)?;

    let key = base64_simd::STANDARD
        .decode_to_vec(file_content.trim())
        .map_app_err(|e| AppError {
            message: "failed to load the AES key".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })?;

    if key.len() != 32 {
        Err(AppError {
            message: "failed to load the AES key'".to_owned(),
            error: Some("expected 32 bytes key".to_owned()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })
    } else {
        unsafe { AES_KEY = Some(key) }

        Ok(())
    }
}

fn load_aes_iv(filename: String) -> AppResult<()> {
    let file_content = load_pem(&filename)?;

    let key = base64_simd::STANDARD
        .decode_to_vec(file_content.trim())
        .map_app_err(|e| AppError {
            message: "failed to load the AES key's IV".to_owned(),
            error: Some(e.to_string()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })?;

    if key.len() != 12 {
        Err(AppError {
            message: "failed to load the AES key's IV".to_owned(),
            error: Some("expected 12 bytes key".to_owned()),
            attr: Some(hashmap! {
                "filename".to_owned() => filename.to_owned(),
            }),
        })
    } else {
        unsafe { AES_IV = Some(key) }

        Ok(())
    }
}

pub fn initialize() -> AppResult<()> {
    let config_clone = config::get_clone();

    load_rsa_private_key(config_clone.secrets.rsa_private_key)?;
    load_rsa_public_key(config_clone.secrets.rsa_public_key)?;
    load_aes_key(config_clone.secrets.aes_key)?;
    load_aes_iv(config_clone.secrets.aes_iv)?;

    Ok(())
}

#[inline]
fn rsa_decrypt(encrypted: &[u8]) -> AppResult<Vec<u8>> {
    const BLOCK_SIZE: usize = 512;

    let private_key = unsafe {
        RSA_PRIVATE_KEY
            .clone()
            .expect("secrets.rs hasn't been initialized")
    };

    let encrypted_len = encrypted.len();

    if encrypted_len % BLOCK_SIZE > 0 {
        return Err(AppError {
            message: "failed to perform a RSA 4096 decryption".to_owned(),
            error: Some("invalid block size".to_owned()),
            attr: Some(hashmap! {
                "block_size".to_owned() => format!("{}", encrypted_len)
            }),
        });
    }

    if encrypted_len > BLOCK_SIZE {
        let mut idx = 0;
        let mut result = Vec::new();

        while idx + BLOCK_SIZE <= encrypted_len {
            let block = encrypted[idx..(idx + BLOCK_SIZE)].to_vec();

            result.append(
                &mut private_key
                    .decrypt(rsa::Pkcs1v15Encrypt, &block)
                    .map_app_err(|e| AppError {
                        message: "failed to perform a RSA 4096 decryption".to_owned(),
                        error: Some(e.to_string()),
                        attr: None,
                    })?,
            );

            idx += BLOCK_SIZE;
        }

        Ok(result)
    } else {
        Ok(private_key
            .decrypt(rsa::Pkcs1v15Encrypt, encrypted)
            .map_app_err(|e| AppError {
                message: "failed to perform a RSA 4096 decryption".to_owned(),
                error: Some(e.to_string()),
                attr: None,
            })?)
    }
}

#[inline]
fn rsa_encrypt(plain: &[u8]) -> AppResult<Vec<u8>> {
    const BLOCK_SIZE: usize = 512;

    let public_key = unsafe {
        RSA_PUBLIC_KEY
            .clone()
            .expect("secrets.rs hasn't been initialized")
    };

    let mut rng = rand::thread_rng();
    let plain_len = plain.len();

    if plain_len > BLOCK_SIZE {
        let mut idx = 0;
        let mut result = Vec::new();

        while idx + BLOCK_SIZE <= plain_len {
            let block = plain[idx..(idx + BLOCK_SIZE)].to_vec();

            result.append(
                &mut public_key
                    .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &block)
                    .map_app_err(|e| AppError {
                        message: "failed to perform a RSA 4096 encryption".to_owned(),
                        error: Some(e.to_string()),
                        attr: None,
                    })?,
            );

            idx += BLOCK_SIZE;
        }

        Ok(result)
    } else {
        Ok(public_key
            .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, plain)
            .map_app_err(|e| AppError {
                message: "failed to perform a RSA 4096 encryption".to_owned(),
                error: Some(e.to_string()),
                attr: None,
            })?)
    }
}

#[inline]
fn aes_decrypt(encrypted: &[u8]) -> AppResult<Vec<u8>> {
    let key = unsafe { AES_KEY.clone().expect("secrets.rs hasn't been initialized") };

    let iv = unsafe { AES_IV.clone().expect("secrets.rs hasn't been initialized") };

    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_app_err(|e| AppError {
        message: "failed to create a AES GCM object".to_owned(),
        error: Some(e.to_string()),
        attr: None,
    })?;

    let nonce = aes_gcm::Nonce::from_slice(&iv[0..12]);

    Ok(cipher.decrypt(nonce, encrypted).map_app_err(|e| AppError {
        message: "failed to perform a AES GCM decryption".to_owned(),
        error: Some(e.to_string()),
        attr: None,
    })?)
}

#[inline]
fn aes_encrypt(plain: &[u8]) -> AppResult<Vec<u8>> {
    let key = unsafe { AES_KEY.clone().expect("secrets.rs hasn't been initialized") };

    let iv = unsafe { AES_IV.clone().expect("secrets.rs hasn't been initialized") };

    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_app_err(|e| AppError {
        message: "failed to create a a AES GCM object".to_owned(),
        error: Some(e.to_string()),
        attr: None,
    })?;

    let nonce = aes_gcm::Nonce::from_slice(&iv[0..12]);

    Ok(cipher.encrypt(nonce, plain).map_app_err(|e| AppError {
        message: "failed to perform a AES GCM encryption".to_owned(),
        error: Some(e.to_string()),
        attr: None,
    })?)
}

pub fn decrypt(encrypted: &[u8]) -> AppResult<Vec<u8>> {
    if encrypted.is_empty() {
        return Err(AppError {
            message: "provided empty data for decryption".to_owned(),
            error: None,
            attr: None,
        });
    }

    let data = rsa_decrypt(encrypted)?;

    Ok(aes_decrypt(&data)?)
}

pub fn encrypt(plain: &[u8]) -> AppResult<Vec<u8>> {
    if plain.is_empty() {
        return Err(AppError {
            message: "provided empty data for encryption".to_owned(),
            error: None,
            attr: None,
        });
    }

    let data = aes_encrypt(plain)?;

    Ok(rsa_encrypt(&data)?)
}
