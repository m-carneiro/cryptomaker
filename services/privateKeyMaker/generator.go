package privateKeyMaker

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
)

func GeneratePrivateKey(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return privateKey, nil
}
