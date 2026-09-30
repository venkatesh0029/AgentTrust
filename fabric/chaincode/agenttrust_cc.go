package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// AgentTrustContract defines the Smart Contract structure for Hyperledger Fabric
type AgentTrustContract struct {
	contractapi.Contract
}

// AgentRecord represents an agent registered on the Fabric ledger
type AgentRecord struct {
	DocType                string `json:"docType"`
	AgentID                string `json:"agent_id"`
	Owner                  string `json:"owner"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	Status                 string `json:"status"`
	RegisteredAt           string `json:"registered_at"`
}

// PolicyRecord represents an authorization policy registered on-chain
type PolicyRecord struct {
	DocType    string                 `json:"docType"`
	PolicyID   string                 `json:"policy_id"`
	AgentID    string                 `json:"agent_id"`
	PolicyData map[string]interface{} `json:"policy_data"`
	CreatedAt  string                 `json:"created_at"`
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

// RegisterAgent registers a new agent on the Fabric ledger
func (c *AgentTrustContract) RegisterAgent(
	ctx contractapi.TransactionContextInterface,
	agentID string,
	owner string,
	certFingerprint string,
	status string,
) (*AgentRecord, error) {
	key := fmt.Sprintf("AGENT_%s", agentID)

	rec := AgentRecord{
		DocType:                "agent",
		AgentID:                agentID,
		Owner:                  owner,
		CertificateFingerprint: certFingerprint,
		Status:                 status,
		RegisteredAt:           time.Now().UTC().Format(time.RFC3339),
	}

	bytes, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}

	err = ctx.GetStub().PutState(key, bytes)
	if err != nil {
		return nil, err
	}

	return &rec, nil
}

// RegisterPolicy registers a versioned policy on-chain
func (c *AgentTrustContract) RegisterPolicy(
	ctx contractapi.TransactionContextInterface,
	policyID string,
	agentID string,
	policyJSON string,
) (*PolicyRecord, error) {
	key := fmt.Sprintf("POLICY_%s", policyID)

	var pdata map[string]interface{}
	err := json.Unmarshal([]byte(policyJSON), &pdata)
	if err != nil {
		return nil, fmt.Errorf("invalid policy JSON: %v", err)
	}

	rec := PolicyRecord{
		DocType:    "policy",
		PolicyID:   policyID,
		AgentID:    agentID,
		PolicyData: pdata,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	bytes, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}

	err = ctx.GetStub().PutState(key, bytes)
	if err != nil {
		return nil, err
	}

	return &rec, nil
}

// EvaluateTransactionPolicy evaluates policy rules on-chain inside chaincode
func (c *AgentTrustContract) EvaluateTransactionPolicy(
	ctx contractapi.TransactionContextInterface,
	agentID string,
	action string,
	amount float64,
	policyID string,
) (string, error) {
	agentKey := fmt.Sprintf("AGENT_%s", agentID)
	agentBytes, err := ctx.GetStub().GetState(agentKey)
	if err != nil || agentBytes == nil {
		return `{"allowed": false, "reason": "CHAINCODE_POLICY_VIOLATION: Agent not registered on ledger"}`, nil
	}

	var agent AgentRecord
	_ = json.Unmarshal(agentBytes, &agent)
	if agent.Status != "ACTIVE" {
		return fmt.Sprintf(`{"allowed": false, "reason": "CHAINCODE_POLICY_VIOLATION: Agent status is '%s'"}`, agent.Status), nil
	}

	targetPolicyID := policyID
	if targetPolicyID == "" {
		targetPolicyID = fmt.Sprintf("POLICY_%s", agentID)
	}
	policyBytes, err := ctx.GetStub().GetState(fmt.Sprintf("POLICY_%s", targetPolicyID))
	if err == nil && policyBytes != nil {
		var policy PolicyRecord
		_ = json.Unmarshal(policyBytes, &policy)
		if maxAmt, ok := policy.PolicyData["maximum_amount"].(float64); ok {
			if amount > maxAmt {
				return fmt.Sprintf(`{"allowed": false, "reason": "CHAINCODE_POLICY_VIOLATION: Amount %.2f exceeds chaincode limit %.2f"}`, amount, maxAmt), nil
			}
		}
	}

	return `{"allowed": true, "reason": "CHAINCODE_APPROVED"}`, nil
}

// RecordActionEvent records an audited action event on-chain with immutability check
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

	// Immutability Check: Prevent overwriting existing committed records
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("Immutability Violation: Action event '%s' already committed to Fabric ledger", eventID)
	}

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
