package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"strings"
	"vem_message_generator/pkg/entities"
	"vem_message_generator/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

var (
	ecdhPublicKey    = flag.String("ecdhPublicKey", "", "ecdh public key")
	ecdhPrivateKey   = flag.String("ecdhPrivateKey", "", "ecdh private key")
	encryptedMessage = flag.String("encryptedMessage", "", "encrypted message")
	validatorsList   = flag.String("validators", "", "comma-separated list of validators")
	pk               = flag.String("pk", "", "private key")
)

// go run cmd/main.go --ecdhPublicKey LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFanlMZVROdnhsZW1DSXVQK2I0ZFdUbUg5b09ibApyeXdqMEFsaExvY2RGc0k5ZEZXRHZjeGtRd096RHdKM3lFa1ZKZENtYlo5cXpYM3ZmWE9zRWl1c2xRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg== \
// --ecdhPrivateKey 050b104e9aea7994bef2993dd5f99dafdf90dd657044fdd8f2a10be9cc25d6f8 --encryptedMessage BBCrhh8WQeQ0FP0XSZaW2Ofprp+vLreTyAVQhtvfJ2FcESEtpqUPK8LNbqvNJ9RmRhtmwka2XB8V7hjEytkqFyjpvJz8qjrsfr+tFGDWq6r8YoB/Yg5nRmrCQtBhJwk8NynkidsqUyDrwJUrXFdgJehsDf7Iw1J5PboaUA2PkEWcHjQC3BbXkAvRpMYahyMg6bGswf6bvUeKR3ygPQlhrigW1WFoecv0vPauqbytZ6cFyWcHUAWPpXoolW6C34WfsGmMEQ8LEyYcdNLvX+8D0MgJ+1FAQsjlxN0G3lHkWvbcUtCTD54b1QdUeEr1hk9xgs4QXYHZnvlE6ZDjIL12tv+sQ47psrtBpUXkDhRm4qq2pfdN4ZEaX2nGG71G4jMpjtvw8rsp0sBZqBkYas467wbgMBxX8bqDXQaw3hjykDKi7fcv9PNrCms1gC+nTyWt+07CPKvz8FGmSVaYNc1smmQLDm6czY8n8KkqBi8Qm24P4URBmWtiR+6wYp/+oAQduAQbCLew+tl3dYPjXnNPISbTuG5f7GjeC0q24NvsPjaF2Z0rIeUXG7z/2LjSA+c/BgS0IU2PZDvIY0XcsPi1m08pKJP70/7+FprzCyCQi0ya9+GAOVengRqRrfQkQ7+h5O5OqiCw/WNTl2csEZWasmIS35y/

func main() {
	flag.Parse()
	if utils.ValidateString(pk) {
		generateVEMRequest()
		return
	}
	// decrypt flow
	if !utils.ValidateString(ecdhPublicKey) || !utils.ValidateString(ecdhPrivateKey) || !utils.ValidateString(encryptedMessage) {
		log.Fatal("invalid params. you must specify ecdhPublicKey, ecdhPrivateKey and encryptedMessage")
	}
	mvPK, err := utils.UnmarshalECDHPublicKey(*ecdhPublicKey)
	if err != nil {
		log.Fatal("failed to unmarshal ecdh public key: ", err)
	}

	privateBytes, err := hex.DecodeString(*ecdhPrivateKey)
	if err != nil {
		log.Fatal("failed to decode private key: ", err)
	}
	curve := ecdh.P256()
	ecdhClientKey, err := curve.NewPrivateKey(privateBytes)
	if err != nil {
		log.Fatal("failed to create private key: ", err)
	}
	commonPrivateKey, err := utils.ComputeECDHSharedSecretGeneric(ecdhClientKey, mvPK)
	if err != nil {
		log.Fatal("failed to compute ecdh shared secret: ", err)
	}
	decryptedVemPayload, err := utils.DecryptECIES(commonPrivateKey, *encryptedMessage)
	if err != nil {
		log.Fatal("failed to decrypt vem payload: ", err)
	}
	log.Println("decrypted vem payload: ", string(decryptedVemPayload))
}

func generateVEMRequest() {
	validatorsPubKeys := strings.Split(*validatorsList, ",")
	if len(validatorsPubKeys) == 0 {
		log.Fatal("no validators provided")
	}
	log.Println("generate vem for validators: ", validatorsPubKeys)

	privateKeyECDSA, err := crypto.HexToECDSA(strings.ReplaceAll(*pk, "0x", ""))
	if err != nil {
		log.Fatal("failed to cast key: ", err)
	}

	ecdhClientKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("failed generate ecdh key: ", err)
	}
	encodedKey, err := utils.MarshalECDHPublicKey(ecdhClientKey.PublicKey())
	if err != nil {
		log.Fatal("failed to marshal ecdh public key: ", err)
	}
	generatedVemRequest, err := json.Marshal(entities.VEMRequest{
		Action:                    entities.RequestActionInitial,
		ValidatorsPubKeys:         validatorsPubKeys,
		ClientECDHPublicKeyBase64: encodedKey,
	})
	if err != nil {
		log.Fatal("failed to marshal sample data: ", err)
	}
	log.Println("======= VEM REQUEST =======")
	log.Println("vem request: ", string(generatedVemRequest))

	log.Println("======= VEM REQUEST SIGNATURE =======")
	clientAddress, err := utils.KeyToAddress(privateKeyECDSA)
	if err != nil {
		log.Fatal("failed to get client address: ", err)
	}

	signature := sign(privateKeyECDSA, string(generatedVemRequest))
	signedContainer, err := json.Marshal(entities.VEMRequestContainer{
		VemRequestID:        uuid.New(),
		VemRequest:          string(generatedVemRequest),
		VemRequestSignature: signature,
		VemRequestSignedBy:  clientAddress.String(),
	})
	if err != nil {
		log.Fatal("failed to marshal signed container: ", err)
	}
	signedBy := checkSign(signature, string(generatedVemRequest))
	if signedBy != clientAddress.String() {
		log.Fatal("signatures mismatch")
	}
	log.Println("======= VEM REQUEST SIGNATURE =======")
	log.Println("vem request signature: ", string(signedContainer))
	log.Println("secret key:", hex.EncodeToString(ecdhClientKey.Bytes()))
	log.Println("secret public key:", encodedKey)
}

func sign(privateKeyECDSA *ecdsa.PrivateKey, payload string) string {
	hash := crypto.Keccak256Hash([]byte(payload))
	signedData, err := crypto.Sign(hash.Bytes(), privateKeyECDSA)
	if err != nil {
		log.Fatal("failed to sign data: ", err)
	}
	return hexutil.Encode(signedData)
}

func checkSign(signature, payload string) string {
	hash := crypto.Keccak256Hash([]byte(payload))
	pkSign, err := crypto.SigToPub(hash[:], common.FromHex(signature))
	if err != nil {
		log.Fatal("failed to recover public key from signature: ", err)
	}
	return crypto.PubkeyToAddress(*pkSign).String()
}
