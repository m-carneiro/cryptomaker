package keyParser

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	DecodePEMKeyFailMessage = "failed to decode PEM block containing public key"
	IsNotRSAKey             = "key is not a RSA public key"
)

func ParsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf(DecodePEMKeyFailMessage)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(IsNotRSAKey)
	}

	return rsaPubKey, nil
}
