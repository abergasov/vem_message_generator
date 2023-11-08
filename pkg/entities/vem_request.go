package entities

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/google/uuid"
)

type (
	RequestVEMAction string
	RequestVEMStatus string
)

const (
	RequestActionInitial RequestVEMAction = "vem_request"

	RequestVEMStatusSuccess RequestVEMStatus = "success"
	RequestVEMStatusError   RequestVEMStatus = "error"
)

type VEMRequest struct {
	Action                    RequestVEMAction `json:"action"`
	ValidatorsPubKeys         []string         `json:"pubkeys"`
	ClientECDHPublicKeyBase64 string           `json:"ecdh_client_pubkey"`
}

type VEMRequestContainer struct {
	VemRequestID uuid.UUID `json:"vem_request_uid"`

	// off-chain section
	VemRequest          string `json:"vem_request,omitempty"` // expect json of VEMRequest
	VemRequestSignature string `json:"vem_request_signature,omitempty"`
	VemRequestSignedBy  string `json:"vem_request_signed_by,omitempty"`
}

func (v *VEMRequestContainer) ErrorRoutingKey() string {
	return ""
}

type VEMResult struct {
	RequestedVems map[string]*phase0.SignedVoluntaryExit `json:"requested_vems"`
}

type VEMResultContainer struct {
	Result             RequestVEMStatus `json:"result"`
	Error              string           `json:"error,omitempty"`
	VemRequestID       uuid.UUID        `json:"vem_request_uid"`
	VemResult          string           `json:"vem_result"`
	ECDHProviderPubKey string           `json:"ecdh_provider_pubkey"`
}
