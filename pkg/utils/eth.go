package utils

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func KeyToAddress(walletPK *ecdsa.PrivateKey) (common.Address, error) {
	publicKeyECDSA, ok := walletPK.Public().(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, fmt.Errorf("failed to cust to ecdsa.PublicKey")
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA), nil
}
