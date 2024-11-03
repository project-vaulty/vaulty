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

use crate::term;

#[derive(Debug, Clone, Default)]
pub struct Arguments {
    pub username: Option<String>,
    pub password: Option<String>,
    pub remote_address: Option<(String, u16)>,
    pub script_file: Option<String>,
    pub tls: bool,
    pub disabled_tls_verification: bool,
}

fn process_command_line() -> anyhow::Result<Arguments> {
    let mut result = Arguments::default();
    let mut url_parsed = false;
    let args: Vec<String> = std::env::args().collect();
    let mut args = args[1..].iter();

    while let Some(arg) = args.next() {
        let uri = url::Url::parse(&arg)
            .map_err(|_| anyhow::anyhow!("the argument '{arg}' is invalid URI"))?;

        if url_parsed {
            return Err(anyhow::anyhow!("multiple URI specified"));
        }

        if uri.scheme().to_lowercase() != "vaulty" {
            return Err(anyhow::anyhow!(
                "unknow schema in URI '{arg}', expected schema is 'vaulty'"
            ));
        }

        if uri.username() != "" {
            result.username = Some(uri.username().to_owned());
        }

        let query = uri.query_pairs();

        for (key, value) in query {
            match key.to_lowercase().as_str() {
                "tls" => match value.to_lowercase().as_str() {
                    "0" | "false" => result.tls = false,
                    "1" | "true" => result.tls = true,
                    _ => {}
                },
                "tlsallowinvalidcerts" => match value.to_lowercase().as_str() {
                    "0" | "false" => result.disabled_tls_verification = false,
                    "1" | "true" => result.disabled_tls_verification = true,
                    _ => {}
                },
                _ => {}
            }
        }

        if let Some(password) = uri.password() {
            result.password = Some(password.to_owned());
        }

        let remote_address = if let Some(remote_address) = uri.domain() {
            remote_address.to_owned()
        } else {
            return Err(anyhow::anyhow!(
                "unknow schema in URI '{arg}', missing domain"
            ));
        };

        let remote_port = if let Some(port) = uri.port() {
            port
        } else {
            if result.tls {
                443
            } else {
                80
            }
        };

        result.remote_address = Some((remote_address, remote_port));
        url_parsed = true;
    }

    Ok(result)
}

pub async fn initialize() -> anyhow::Result<Arguments> {
    let mut arguments = process_command_line()?;

    if arguments.remote_address.is_none() {
        if arguments.tls {
            arguments.remote_address = Some(("127.0.0.1".to_string(), 443))
        } else {
            arguments.remote_address = Some(("127.0.0.1".to_string(), 80))
        }
    }

    if arguments.username.is_none() {
        arguments.username = Some(term::prompt_input("username")?);
    }

    if arguments.password.is_none() {
        arguments.password = Some(term::prompt_password("password")?);
    }

    Ok(arguments)
}
