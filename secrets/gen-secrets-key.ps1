openssl genpkey -algorithm RSA -out secret-rsa-private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in secret-rsa-private.pem -out secret-rsa-public.pem

[System.Convert]::ToBase64String((1..32 | ForEach-Object { [byte](Get-Random -Minimum 0 -Maximum 256) })) | Out-File -Encoding ASCII secret-aes.key
[System.Convert]::ToBase64String((1..12 | ForEach-Object { [byte](Get-Random -Minimum 0 -Maximum 256) })) | Out-File -Encoding ASCII secret-iv.key
