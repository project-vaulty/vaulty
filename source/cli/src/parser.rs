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

const ALLOWED_CHARS: &str = "_-1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";

pub fn parse<'a>(command: &str) -> Result<Vec<(String, Option<String>)>, &'a str> {
    let mut result: Vec<(String, Option<String>)> = Vec::new();
    let mut token = String::new();
    let mut argument = String::new();
    let mut in_argument = false;
    let mut in_quote1 = false;
    let mut in_quote2 = false;
    let mut previous_char = None;
    let mut argument_already_defined = false;

    let command = command.trim();

    if command.is_empty() {
        return Ok(Vec::new());
    }

    for (len, c) in command.chars().enumerate() {
        if in_argument {
            if c == '"' {
                if let Some(pc) = previous_char {
                    if pc != '\\' {
                        in_quote1 = !in_quote1;
                    }
                } else {
                    in_quote1 = !in_quote1;
                }
            } else if c == '\'' {
                if let Some(pc) = previous_char {
                    if pc != '\\' {
                        in_quote2 = !in_quote2;
                    }
                } else {
                    in_quote2 = !in_quote2;
                }
            } else if c == ')' && !in_quote1 && !in_quote2 {
                in_argument = false;
                argument_already_defined = true;
            } else {
                argument.push(c);
            }
        } else {
            if c == '(' && !argument_already_defined {
                in_argument = true;
            } else if c == '.' || len == command.len() {
                result.push((
                    token,
                    if argument.is_empty() {
                        None
                    } else {
                        Some(argument.clone())
                    },
                ));

                token = String::new();
                argument = String::new();
                in_argument = false;
                in_quote1 = false;
                in_quote2 = false;
                argument_already_defined = false;
            } else if argument_already_defined {
                return Err("illformed command");
            } else {
                if ALLOWED_CHARS.contains(c) {
                    token.push(c);
                } else {
                    return Err("illformed command");
                }
            }
        }

        previous_char = Some(c);
    }

    result.push((
        token,
        if argument.is_empty() {
            None
        } else {
            Some(argument.clone())
        },
    ));

    return Ok(result);
}
