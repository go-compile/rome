package main

import (
	"crypto/sha1"
	"fmt"

	"github.com/go-compile/rome/parse"
)

func main() {
	fmt.Println("P192r1 Private:")
	parsePrivate([]byte(`-----BEGIN EC PRIVATE KEY-----
MF4CAQEEGIGv8cxcdkitRLKR8TQf2SGOoFqzO8Hs4KAJBgcrhkjOPQEDoTQDMgAE
jBSOPviPICiS3A8oRgjYfkA3WMUCJvGclKooR+REWIBCvTEwaQP7DSTooC5z4BdB
-----END EC PRIVATE KEY-----`))

	fmt.Println("P192r1 Public:")
	parsePublic([]byte(`-----BEGIN EC PUBLIC KEY-----
MEgwEgYHKoZIzj0CAQYHK4ZIzj0BAwMyAASMFI4++I8gKJLcDyhGCNh+QDdYxQIm
8ZyUqihH5ERYgEK9MTBpA/sNJOigLnPgF0E=
-----END EC PUBLIC KEY-----`))
}

func parsePrivate(priv []byte) {
	k, err := parse.Private(priv)
	if err != nil {
		panic(err)
	}

	fmt.Printf(" Curve: %s\n Fingerprint: %x\n", k.Public().Name(), k.Public().Fingerprint(sha1.New()))
}

func parsePublic(pub []byte) {
	k, err := parse.Public(pub)
	if err != nil {
		panic(err)
	}

	fmt.Printf(" Curve: %s\n Fingerprint: %x\n", k.Name(), k.Fingerprint(sha1.New()))
}
