openssl ecparam -genkey -name secp256r1 -noout -out iam-ecdsa-private.pem.temp
openssl ec -in iam-ecdsa-private.pem.temp -pubout -out iam-ecdsa-public.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in iam-ecdsa-private.pem.temp -out iam-ecdsa-private.pem
rm iam-ecdsa-private.pem.temp
