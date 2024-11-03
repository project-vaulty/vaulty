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

#[derive(Debug, Clone, Copy)]
pub struct Exit(i32);

pub static LOG: Exit = Exit(1);
pub static CONFIG: Exit = Exit(2);
pub static SECRETS: Exit = Exit(3);
pub static IAM: Exit = Exit(4);
pub static SERVER: Exit = Exit(5);
pub static DB: Exit = Exit(5);

impl Exit {
    pub fn exit(self) {
        std::process::exit(self.0);
    }
}
