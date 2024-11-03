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

use argon2::password_hash::{
    rand_core::OsRng,
    PasswordHasher, SaltString
};

fn main() {
    let args: Vec<String> = std::env::args().into_iter().collect();

    for password in &args[1..] {
        let config = argon2::Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let hash = config.hash_password(password.as_bytes(), &salt).expect("failed to hash");

        println!("{password}\n - {hash}");
    }
}
