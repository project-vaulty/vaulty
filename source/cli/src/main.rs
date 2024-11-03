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

#[cfg(not(target_os = "windows"))]
use std::os::fd::AsRawFd;

pub mod cmd;
pub mod cmdline;
pub mod parser;
pub mod permission;
pub mod session;
pub mod term;

#[cfg(not(target_os = "windows"))]
fn fix_terminal() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    let mut termios = termios::Termios::from_fd(fd)?;

    termios.c_lflag |= termios::ECHO | termios::ICANON | termios::ISIG;
    termios.c_iflag |= termios::ICRNL;

    termios::tcsetattr(fd, termios::TCSANOW, &termios)?;

    Ok(())
}

#[tokio::main]
async fn main() {
    println!("Copyright (C) 2024  S. Ivanov\n");

    #[cfg(not(target_os = "windows"))]
    let _ = fix_terminal();

    let arguments = match cmdline::initialize().await {
        Ok(value) => value,
        Err(e) => {
            errorln!("{}", e.to_string());
            return;
        }
    };

    if let Err(e) = session::handle(arguments).await {
        errorln!("{}", e.to_string());
        return;
    }
}
