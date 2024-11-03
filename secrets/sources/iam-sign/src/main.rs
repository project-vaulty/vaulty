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

use p256::{ecdsa::signature::Signer, pkcs8::DecodePrivateKey};
use base64::Engine;

pub fn initialize(filename: String) -> anyhow::Result<p256::ecdsa::SigningKey> {
    let file_content = std::fs::read_to_string(&filename)
        .map_err(|e| anyhow::anyhow!("failed to read from '{filename}', {}", e.to_string()))?;

    let result = p256::ecdsa::SigningKey::from_pkcs8_pem(&file_content).map_err(|e| {
        anyhow::anyhow!("failed to load public key '{filename}', {}", e.to_string())
    })?;

    Ok(result)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().into_iter().collect();

    if args.len() < 3 {
        eprintln!("invalid number of args");
        return Ok(());
    }

    let signing_key = initialize(args[1].clone())?;

    for value in &args[2..] {
        let signature: p256::ecdsa::Signature = signing_key.sign(value.clone().as_bytes());
        let signature = signature.to_der().to_bytes();
        let friendly = signature.clone();
        let string_hex = signature
            .iter()
            .fold(String::new(), |v1, v2| format!("{v1}\\x{:02X}", v2));

        let encoded = base64::prelude::BASE64_STANDARD.encode(signature);

        println!("{value}\n - \"{}\"\n - {}\n - {:?}", string_hex, encoded, friendly);
    }

    Ok(())
}
