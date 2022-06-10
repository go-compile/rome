package brainpool

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/ebfe/brainpool"
	"github.com/go-compile/rome"
)

// GenerateP160r will create a new Brainpool P160r elliptic curve public/private key pair
func GenerateP160r() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P160r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP160r1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP160t1 will create a new Brainpool P160t1 elliptic curve public/private key pair
func GenerateP160t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P160t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP160t1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP192r1 will create a new Brainpool P192r1 elliptic curve public/private key pair
func GenerateP192r1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P192r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP192r1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP192t1 will create a new Brainpool P192t1 elliptic curve public/private key pair
func GenerateP192t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P192t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP192t1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP224r1 will create a new Brainpool P224r1 elliptic curve public/private key pair
func GenerateP224r1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P224r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP224r1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP224t1 will create a new Brainpool P224t1 elliptic curve public/private key pair
func GenerateP224t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P224t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP224t1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP256r1 will create a new Brainpool P256r1 elliptic curve public/private key pair
func GenerateP256r1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP256r1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP256t1 will create a new Brainpool P256t1 elliptic curve public/private key pair
func GenerateP256t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P256t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k.Curve.Params().Name = "brainpoolP256t1"

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}
