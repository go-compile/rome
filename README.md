# Rome

The Elliptic and Edward Curve cryptography library built for multi-curve use.

# Curves

- nist P-521
- nist P-384
- nist P-256
- nist P-224
- Ed25519

More to come...

# Features

- Generate key
- Export (Public, Private) PEM **and** ASN.1 DER bytes
- Import (Public, Private) PEM **and** ASN.1 DER bytes
- Sign (ASN.1 format)
- Verify

<div align=center>

## Implemented Curves & Features

| Curve             |      Type      | Sign | Verify | Encrypt | DH  |
| :---------------- | :------------: | :--: | :----: | :-----: | :-: |
| Nist P-521        | Elliptic Curve |  ✔   |   ✔    |    ✖    |  ✔  |
| Nist P-384        | Elliptic Curve |  ✔   |   ✔    |    ✖    |  ✔  |
| Nist P-256        | Elliptic Curve |  ✔   |   ✔    |    ✖    |  ✔  |
| Nist P-224        | Elliptic Curve |  ✔   |   ✔    |    ✖    |  ✔  |
| Ed25519           |  Edward Curve  |  ✔   |   ✔    |   n/a   | n/a |
| x25519/Curve25519 | Elliptic Curve |  ✖   |   ✖    |    ✖    |  ✖  |
| x448 Goldilocks   | Elliptic Curve |  ✖   |   ✖    |    ✖    |  ✖  |

</div>

# Todo

- ECIES: nist curves, Curve25519, Curve448
- ECDH
- Maybe RSA
- secp256k1
- saltpack
