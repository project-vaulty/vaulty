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

use std::io::Write;

use anyhow::Context;
use rustyline::config::Configurer;

#[macro_export]
macro_rules! outputln {
    ($fmt:expr $(, $args:expr)*) => {
        {
            use std::io::Write;

            let mut stdout = std::io::stdout();
            let message = format!($fmt $(, $args)*);
            let _ = write!(stdout, "{message}\n");
        }
    };
}

#[macro_export]
macro_rules! errorln {
    ($fmt:expr $(, $args:expr)*) => {
        {
            use std::io::Write;
            use crossterm::style::Stylize;

            let mut stdout = std::io::stdout();
            let message = format!($fmt $(, $args)*).dark_red();

            let _ = write!(stdout, "{message}{}", "\n".reset());
        }
    };
}

pub fn prompt_input(initial_message: &str) -> anyhow::Result<String> {
    let mut input = String::new();

    print!("{initial_message}: ");

    let _ = std::io::stdout().flush();
    let _ = std::io::stdin()
        .read_line(&mut input)
        .context("failed to read from stdin")?;

    Ok(input.trim().to_owned())
}

pub fn prompt_password(initial_message: &str) -> anyhow::Result<String> {
    let input = rpassword::prompt_password(format!("{initial_message}: "))
        .context("failed to read from stdin")?;

    Ok(input.to_owned())
}

struct MultiLineValidator;

impl rustyline::validate::Validator for MultiLineValidator {
    fn validate(
        &self,
        context: &mut rustyline::validate::ValidationContext<'_>,
    ) -> Result<rustyline::validate::ValidationResult, rustyline::error::ReadlineError> {
        let input = context.input();
        let mut brace_count = 0;
        let mut in_quotes1 = false;
        let mut in_quotes2 = false;
        let mut chars = input.chars().peekable();
        let mut previous_char = None;

        while let Some(c) = chars.next() {
            match c {
                '{' if !in_quotes1 && !in_quotes2 => brace_count += 1,
                '}' if !in_quotes1 && !in_quotes2 => brace_count -= 1,
                '"' => {
                    if let Some(pc) = previous_char {
                        if pc != '\\' {
                            in_quotes1 = !in_quotes1;
                        }
                    } else {
                        in_quotes1 = !in_quotes1;
                    }
                }
                '\'' => {
                    if let Some(pc) = previous_char {
                        if pc != '\\' {
                            in_quotes2 = !in_quotes2;
                        }
                    } else {
                        in_quotes2 = !in_quotes2;
                    }
                }
                _ => {}
            }

            previous_char = Some(c);
        }

        if brace_count == 0 && !in_quotes1 && !in_quotes2 {
            Ok(rustyline::validate::ValidationResult::Valid(None))
        } else {
            Ok(rustyline::validate::ValidationResult::Incomplete)
        }
    }
}

#[derive(
    rustyline::Completer,
    rustyline::Helper,
    rustyline::Highlighter,
    rustyline::Hinter,
    rustyline::Validator,
)]
struct InputValidator {
    #[rustyline(Validator)]
    validator: MultiLineValidator,
    #[rustyline(Highlighter)]
    highlighter: rustyline::highlight::MatchingBracketHighlighter,
}

pub struct CommandInput {
    rl: rustyline::Editor<InputValidator, rustyline::history::FileHistory>,
}

impl CommandInput {
    pub fn new() -> anyhow::Result<Self> {
        let h = InputValidator {
            validator: MultiLineValidator,
            highlighter: rustyline::highlight::MatchingBracketHighlighter::new(),
        };

        let mut rl = rustyline::Editor::new()?;

        rl.set_helper(Some(h));
        let _ = rl.set_max_history_size(20);

        Ok(CommandInput { rl })
    }

    pub fn prompt(
        &mut self,
        message: &str,
    ) -> anyhow::Result<String, rustyline::error::ReadlineError> {
        let input = self.rl.readline(message)?;

        if let Err(_) = self.rl.add_history_entry(input.clone()) {
            let _ = self.rl.clear_history();
        }

        Ok(input)
    }
}
