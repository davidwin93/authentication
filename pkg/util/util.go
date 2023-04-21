package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"golang.org/x/crypto/bcrypt"
)

type BcryptPasswordHandler struct{}

func (b *BcryptPasswordHandler) HardenPassword(password string) (string, error) {
	bcrpytPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return base64.RawURLEncoding.EncodeToString(bcrpytPassword), err
}
func (b *BcryptPasswordHandler) IsPasswordValid(b64Password, password string) (bool, error) {
	hashed, err := base64.RawURLEncoding.DecodeString(b64Password)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err == nil {
		return true, nil
	}
	return false, err
}

func GenerateRSAPair() ([]byte, []byte) {
	bitSize := 2048

	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	// Extract public component.
	pub := key.Public()

	// Encode private key to PKCS#1 ASN.1 PEM.
	privPEM, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privPEM,
		},
	)

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubCert, _ := x509.MarshalPKIXPublicKey(pub.(*rsa.PublicKey))
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubCert,
		},
	)
	return keyPEM, pubPEM
}
