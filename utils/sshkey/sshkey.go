package sshkey

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

func GetKeySize(key ssh.PublicKey) int {
	switch key.Type() {
	case "ssh-rsa":
		return getRSASize(key)
	case "ssh-ed25519":
		return 256
	case "ecdsa-sha2-nistp256":
		return 256
	case "ecdsa-sha2-nistp384":
		return 384
	case "ecdsa-sha2-nistp521":
		return 521
	default:
		return 0
	}
}

func getRSASize(key ssh.PublicKey) int {
	data := key.Marshal()
	r := bytes.NewReader(data)

	if _, err := readString(r); err != nil {
		return 0
	}
	if _, err := readString(r); err != nil {
		return 0
	}

	modulus, err := readString(r)
	if err != nil {
		return 0
	}

	for len(modulus) > 0 && modulus[0] == 0 {
		modulus = modulus[1:]
	}

	return len(modulus) * 8
}

func readString(r *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	str := make([]byte, length)
	if _, err := r.Read(str); err != nil {
		return nil, err
	}
	return str, nil
}
