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
- Maybe RSA
- secp256k1
- saltpack

# Install

```sh
go get -u github.com/go-compile/rome
```

# Examples

Full code [examples can be found ./examples/](./examples/)

```go
package main

import (
	"fmt"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p256"
)

func main() {
	// Generate a nist P256 Elliptic Curve
	k, err := p256.Generate()
	if err != nil {
		panic(err)
	}

	printKey("P256", k)
}

func printKey(name string, k rome.PrivateKey) {
	// Format private key using PEM and ASN.1 DER bytes
	private, err := k.Private()
	if err != nil {
		panic(err)
	}

	public, err := k.Public().Key()
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s:\n Private:\n%s\n Public:\n%s\n",
		name, string(private), string(public))
}
```

Output:

```
P256:
Private:
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIATPRwGmsr81mgiH1Tf+yntyUcj0m9Ta3UsaWrgPjZtKoAoGCCqGSM49
AwEHoUQDQgAENjGsmnjl4dXbRur5AfzlDxq6Bp0BQafwM7DJdhSv1yUNRF3+oDsw
mZ9MD9z6VjjBh8REN6e0SDIM/IJCZL84DA==
-----END EC PRIVATE KEY-----

Public:
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENjGsmnjl4dXbRur5AfzlDxq6Bp0B
QafwM7DJdhSv1yUNRF3+oDswmZ9MD9z6VjjBh8REN6e0SDIM/IJCZL84DA==
-----END EC PUBLIC KEY-----
```
