package utils

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func MarshalECDHPublicKey(pk *ecdh.PublicKey) (string, error) {
	ecdhSKBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key into PKIX format")
	}
	ecdhSKPEMBlock := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ecdhSKBytes,
		},
	)

	return base64.StdEncoding.EncodeToString(ecdhSKPEMBlock), nil
}
