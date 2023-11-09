package utils

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var (
	p256N, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
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

func UnmarshalECDHPublicKey(encodedPK string) (*ecdh.PublicKey, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(encodedPK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM block from base64. err: %w", err)
	}
	block, _ := pem.Decode(pkBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pkRaw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDH PKIX public key. err: %w", err)
	}

	ecdsaPK, isECDSAPubKey := pkRaw.(*ecdsa.PublicKey)
	if !isECDSAPubKey {
		return nil, fmt.Errorf("key not ECDSA-compatible, most probably key not on one of NIST curves but has to be on P256 curve")
	}

	return ecdsaPK.ECDH()
}

func ComputeECDHSharedSecret(clientPublicKey string) (ourSK *ecdh.PrivateKey, sharedSecret *ecdsa.PrivateKey, err error) {
	clientECDHPubKey, err := UnmarshalECDHPublicKey(clientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse client ECDH public key from request: %w", err)
	}
	ourSK, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDH private key and it's strange: %w", err)
	}
	sharedSecret, err = ComputeECDHSharedSecretGeneric(ourSK, clientECDHPubKey)
	return
}

func ComputeECDHSharedSecretGeneric(ourSecretKey *ecdh.PrivateKey, clientPublicKey *ecdh.PublicKey) (*ecdsa.PrivateKey, error) {
	sharedSecretBytes, err := ourSecretKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ECDH shared secret: %w", err)
	}
	return ConvertECDHtoECDSAPrivateKeyFromBytes(sharedSecretBytes)
}

func EncryptECIES(ecdhSharedSecretPK *ecdsa.PublicKey, data []byte) (string, error) {
	encryptedSK, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(ecdhSharedSecretPK), data, nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed ECIES to encrypt validator secret key with computed ECDH shared secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encryptedSK), nil
}

func DecryptECIES(ecdhSharedSecret *ecdsa.PrivateKey, data string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECIES encrypted data from base64. err: %w", err)
	}
	return ecies.ImportECDSA(ecdhSharedSecret).Decrypt(ciphertext, nil, nil)
}

func ConvertECDHtoECDSAPrivateKey(ecdhPK *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	return ConvertECDHtoECDSAPrivateKeyFromBytes(ecdhPK.Bytes())
}

func ConvertECDHtoECDSAPrivateKeyFromBytes(secretBytes []byte) (*ecdsa.PrivateKey, error) {
	sk := new(ecdsa.PrivateKey)
	sk.PublicKey.Curve = elliptic.P256()
	if 8*len(secretBytes) != sk.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", sk.Params().BitSize)
	}
	sk.D = new(big.Int).SetBytes(secretBytes)

	// The sk.D must < N
	if sk.D.Cmp(p256N) >= 0 {
		return nil, fmt.Errorf("invalid secret key, >=N")
	}
	// The sk.D must not be zero or negative.
	if sk.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid secret key, zero or negative")
	}

	sk.PublicKey.X, sk.PublicKey.Y = sk.PublicKey.Curve.ScalarBaseMult(secretBytes)
	if sk.PublicKey.X == nil {
		return nil, fmt.Errorf("invalid secret key")
	}
	return sk, nil
}

func ConvertECDHtoECDSAPublicKey(ecdhPK string) (*ecdsa.PublicKey, error) {
	pKBytes, err := base64.StdEncoding.DecodeString(ecdhPK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM block from base64: %w", err)
	}
	block, _ := pem.Decode(pKBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block: %w", err)
	}

	pKRaw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDH PKIX public key: %w", err)
	}
	ecdsaPubKey, isECDSA := pKRaw.(*ecdsa.PublicKey)
	if !isECDSA {
		return nil, fmt.Errorf("key not ECDSA-compatible, most probably key not on one of NIST curves but has to be on P256 curve")
	}
	return ecdsaPubKey, nil
}
