$currentPath = Get-Location

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Not running as Administrator"
    Exit
}

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" + [System.Environment]::GetEnvironmentVariable("Path","Machine")

choco install openssl

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" + [System.Environment]::GetEnvironmentVariable("Path","Machine")

git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install openssl:x64-windows-static

cd $currentPath

$env:OPENSSL_DIR = (Get-Location).Path + "\vcpkg\packages\openssl_x64-windows-static"
$env:OPENSSL_INCLUDE_DIR = "$env:OPENSSL_DIR\include"
$env:OPENSSL_LIB_DIR = "$env:OPENSSL_DIR\lib"

cd source/vault
cargo build --release
cp target/release/vaulty.exe $currentPath/vaulty.exe

cd ../cli
cargo build --release
cp target/release/vaulty-cli.exe $currentPath/vaulty-cli.exe
