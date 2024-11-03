openssl genpkey -algorithm RSA -out secret-rsa-private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in secret-rsa-private.pem -out secret-rsa-public.pem

head -c 32 /dev/urandom | base64 > secret-aes.key
head -c 12 /dev/urandom | base64 > secret-iv.key