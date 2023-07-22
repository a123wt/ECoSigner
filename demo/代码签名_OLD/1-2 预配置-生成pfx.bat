@echo off

set PRIVATE_KEY=private.pem
set CERTIFICATE=issued_crt.crt
set PFX_FILE=private.pfx


echo generate pfx file
openssl pkcs12 -export -in %CERTIFICATE% -inkey %PRIVATE_KEY% -out %PFX_FILE%
echo success

echo All Success

pause
