package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// AgentTrustContract defines the Smart Contract structure
type AgentTrustContract struct {
	contractapi.Contract
}

// ActionEvent represents an audited action on the permissioned ledger
type ActionEvent struct {
	DocType           string `json:"docType"`
	EventID           string `json:"event_id"`
	RequestID         string `json:"request_id"`
	AgentID           string `json:"agent_id"`
	Action            string `json:"action"`
	Resource          string `json:"resource"`
	Decision          string `json:"decision"`
	Reason            string `json:"reason"`
	PolicyID          string `json:"policy_id"`
	PolicyVersion     string `json:"policy_version"`
	EvidenceReference string `json:"evidence_reference"`
	EvidenceHash      string `json:"evidence_hash"`
	Timestamp         string `json:"timestamp"`
}

// VerificationResult represents evidence hash verification state
type VerificationResult struct {
	Found            bool   `json:"found"`
	StoredHash       string `json:"stored_hash"`
	RecalculatedHash string `json:"recalculated_hash"`
	Verified         bool   `json:"verified"`
	Status           string `json:"status"`
}

// RecordActionEvent records an execution event on the blockchain ledger
func (c *AgentTrustContract) RecordActionEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	requestID string,
	agentID string,
	action string,
	resource string,
	decision string,
	reason string,
	policyID string,
	policyVersion string,
	evidenceRef string,
	evidenceHash string,
) (*ActionEvent, error) {
	key := fmt.Sprintf("EVENT_%s", eventID)

	eventRecord := ActionEvent{
		DocType:           "action_event",
		EventID:           eventID,
		RequestID:         requestID,
		AgentID:           agentID,
		Action:            action,
		Resource:          resource,
		Decision:          decision,
		Reason:            reason,
		PolicyID:          policyID,
		PolicyVersion:     policyVersion,
		EvidenceReference: evidenceRef,
		EvidenceHash:      evidenceHash,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}

	eventBytes, err := json.Marshal(eventRecord)
	if err != nil {
		return nil, err
	}

	err = ctx.GetStub().PutState(key, eventBytes)
	if err != nil {
		return nil, err
	}

	return &eventRecord, nil
}

// VerifyEvidenceReference verifies an off-chain recalculated evidence hash against ledger state
func (c *AgentTrustContract) VerifyEvidenceReference(
	ctx contractapi.TransactionContextInterface,
	evidenceRef string,
	recalculatedHash string,
) (*VerificationResult, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("EVENT_", "EVENT_\uffff")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var event ActionEvent
		err = json.Unmarshal(queryResponse.Value, &event)
		if err != nil {
			continue
		}

		if event.EvidenceReference == evidenceRef {
			isMatch := strings.EqualFold(event.EvidenceHash, recalculatedHash)
			status := "VERIFIED"
			if !isMatch {
				status = "TAMPERING_DETECTED"
			}
			return &VerificationResult{
				Found:            true,
				StoredHash:       event.EvidenceHash,
				RecalculatedHash: recalculatedHash,
				Verified:         isMatch,
				Status:           status,
			}, nil
		}
	}

	return &VerificationResult{
		Found:    false,
		Verified: false,
		Status:   "NOT_FOUND",
	}, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&AgentTrustContract{})
	if err != nil {
		fmt.Printf("Error creating AgentTrust chaincode: %s\n", err)
		return
	}

	if err := cc.Start(); err != nil {
		fmt.Printf("Error starting AgentTrust chaincode: %s\n", err)
	}
}
