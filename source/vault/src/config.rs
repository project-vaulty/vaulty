use maplit::hashmap;

use crate::app_error::{AppError, AppErrorResult, AppResult};

const CONFIG_OBJECT_FILENAME: &str = "config.yml";

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigDb {
    pub location: String,
    #[cfg(debug_assertions)]
    pub debug_populate: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigSecrets {
    pub rsa_private_key: String,
    pub rsa_public_key: String,
    pub aes_key: String,
    pub aes_iv: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigAccessKeys {
    pub signing_key: String,
    pub verifying_key: String,
    pub delay_unsuccessful_attempts_millis: u64,
    pub acces_key_length: usize,
    pub secret_access_key_length: usize,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigUsers {
    pub delay_unsuccessful_attempts_millis: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigServerTls {
    pub certificate: String,
    pub key: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigServer {
    pub listen_address: String,
    pub listen_port: u16,
    pub tls: Option<ConfigServerTls>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConfigLog {
    pub filename: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    pub node_name: String,
    pub log: Option<ConfigLog>,
    pub db: ConfigDb,
    pub secrets: ConfigSecrets,
    pub access_keys: ConfigAccessKeys,
    pub users: ConfigUsers,
    pub server: ConfigServer,
}

pub static mut CONFIG_OBJECT: Option<Config> = None;

pub fn get_clone() -> Config {
    unsafe { CONFIG_OBJECT.clone().unwrap() }
}

pub fn initialize(filename: Option<String>) -> AppResult<()> {
    let filename = if let Some(filename) = filename {
        filename
    } else {
        CONFIG_OBJECT_FILENAME.to_string()
    };

    let file_content = std::fs::read_to_string(&filename).map_app_err(|e| AppError {
        message: "failed to read the content".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename.clone()
        }),
    })?;

    let object: Config = serde_yaml::from_str(&file_content).map_app_err(|e| AppError {
        message: "failed to deserialize the content".to_owned(),
        error: Some(e.to_string()),
        attr: Some(hashmap! {
            "filename".to_owned() => filename
        }),
    })?;

    unsafe {
        CONFIG_OBJECT = Some(object);
    }

    Ok(())
}
