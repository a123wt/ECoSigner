@echo off

set OPENSSL_CONF=openssl.cnf

set CA_PRIVATE_KEY=CA.key
set CA_CERTIFICATE=CA.crt

set REQ_FILE=csr.pem
set CERT_FILE=issued_crt.crt


openssl x509 -req -in %REQ_FILE% -CA %CA_CERTIFICATE% -CAkey %CA_PRIVATE_KEY% -CAcreateserial -out %CERT_FILE% -days 365

if errorlevel 1 (
    echo Failed to issue certificate.
    exit /b 1
) else (
    echo Certificate issued successfully.
    exit /b 0
)
