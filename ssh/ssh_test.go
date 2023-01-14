package ssh_test

import (
	"testing"

	"github.com/go-compile/rome"
	"github.com/go-compile/rome/brainpool"
	"github.com/go-compile/rome/ed25519"
	"github.com/go-compile/rome/p256"
	"github.com/go-compile/rome/p384"
	"github.com/go-compile/rome/p521"
	"github.com/go-compile/rome/ssh"
)

func TestP256SSH(t *testing.T) {
	k, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ssh.ToKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
}

func TestP384SSH(t *testing.T) {
	k, err := p384.Generate()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ssh.ToKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
}

func TestP521SSH(t *testing.T) {
	k, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ssh.ToKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
}

func TestP256SSHMarshaled(t *testing.T) {
	k, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	buf, _, err := ssh.ToMarshaledKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) == 0 {
		t.Fatal("key too short")
	}
}

func TestP384SSHMarshaled(t *testing.T) {
	k, err := p384.Generate()
	if err != nil {
		t.Fatal(err)
	}

	buf, _, err := ssh.ToMarshaledKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) == 0 {
		t.Fatal("key too short")
	}
}

func TestP521SSHMarshaled(t *testing.T) {
	k, err := p521.Generate()
	if err != nil {
		t.Fatal(err)
	}

	buf, _, err := ssh.ToMarshaledKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) == 0 {
		t.Fatal("key too short")
	}
}

func TestUnsupportedBrainpoolKey(t *testing.T) {
	k, err := brainpool.GenerateP256r1()
	if err != nil {
		t.Fatal(err)
	}

	buf, _, err := ssh.ToMarshaledKey(k.Public())
	if err == nil {
		t.Fatal("expected error")
	}

	if len(buf) > 0 {
		t.Fatal("expected key buf to be empty")
	}
}

func TestUnsupportedEd25519Key(t *testing.T) {
	k, err := ed25519.Generate()
	if err != nil {
		t.Fatal(err)
	}

	buf, _, err := ssh.ToMarshaledKey(k.Public())
	if err == nil {
		t.Fatal("expected error")
	}

	if len(buf) > 0 {
		t.Fatal("expected key buf to be empty")
	}
}

func TestUnsupportedRSAKey(t *testing.T) {
	k, err := rome.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}

	buf, _, err := ssh.ToMarshaledKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) < 1 {
		t.Fatal("expected key buf to not be empty")
	}
}
