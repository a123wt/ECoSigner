@echo off

set PRIVATE_KEY=private.pem
set CERTIFICATE_REQUEST=csr.pem

echo keygen 
openssl genpkey -algorithm RSA -out %PRIVATE_KEY%
echo success

echo create csr
openssl req -new -key %PRIVATE_KEY% -out %CERTIFICATE_REQUEST%
echo success


pause