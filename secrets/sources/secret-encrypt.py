"""
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
"""

import sys
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def init_aes() -> tuple[bytes, bytes]:
    key = None
    iv = None

    with open('secret-aes.key', 'r') as file:
        key = base64.standard_b64decode(file.read().strip())

    with open('secret-iv.key', 'r') as file:
        iv = base64.standard_b64decode(file.read().strip())

    return (key, iv)

def init_rsa() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = None
    public_key = None

    with open('secret-rsa-private.pem', 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(), password=None)

    with open('secret-rsa-public.pem', 'rb') as file:
        public_key = serialization.load_pem_public_key(file.read())

    return [private_key, public_key]

(aes_key, aes_iv) = init_aes()
(rsa_private_key, rsa_public_key) = init_rsa()

for value in sys.argv[1:]:
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(aes_iv, value.encode("UTF-8"), None)
    encrypted = rsa_public_key.encrypt(encrypted, padding=padding.PKCS1v15())

    digest = hashes.Hash(hashes.SHA512())
    digest.update(encrypted)
    hash = str(base64.standard_b64encode(digest.finalize()))
    encrypted = str(base64.standard_b64encode(encrypted))

    print(f"Plain: {value}\n - SHA256: {hash}\n - {encrypted}")
