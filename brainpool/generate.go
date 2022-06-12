package brainpool

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/go-compile/rome"
	brainpool "github.com/go-compile/rome/brainpool/bcurves"
)

// GenerateP160r will create a new Brainpool P160r elliptic curve public/private key pair
func GenerateP160r() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P160r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

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

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP320r1 will create a new Brainpool elliptic curve public/private key pair
func GenerateP320r1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P320r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP320t1 will create a new Brainpool elliptic curve public/private key pair
func GenerateP320t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P320t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP384r1 will create a new Brainpool elliptic curve public/private key pair
func GenerateP384r1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P384r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP384t1 will create a new Brainpool elliptic curve public/private key pair
func GenerateP384t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P384t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP512r1 will create a new Brainpool elliptic curve public/private key pair
func GenerateP512r1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P512r1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}

// GenerateP512t1 will create a new Brainpool elliptic curve public/private key pair
func GenerateP512t1() (*rome.ECKey, error) {

	k, err := ecdsa.GenerateKey(brainpool.P512t1(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ecdsa curves share a common interface.
	// Go's elliptic.Curve only comes with Nist curves thus the package nist
	// is where all the code for interfacing with such curves are.
	return rome.NewECCurve(k), nil
}
