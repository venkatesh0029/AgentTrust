package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type verifyRequest struct {
	EvidenceRef  string `json:"evidence_ref"`
	ExpectedHash string `json:"expected_hash"`
}

type apiResponse struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func requiredEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func gatewayContractNames() (string, string) {
	channelName := requiredEnv(
		"FABRIC_CHANNEL_NAME",
		"agenttrust-channel",
	)
	chaincodeName := requiredEnv(
		"FABRIC_CHAINCODE_NAME",
		"agenttrust",
	)
	return channelName, chaincodeName
}

func firstFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return filepath.Join(dir, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("no files found in %s", dir)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health is unauthenticated only because the bridge will have
		// no published host port and will be reachable on a private network.
		if r.Method == http.MethodGet && r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 ||
			!strings.EqualFold(parts[0], "Bearer") ||
			subtle.ConstantTimeCompare(
				[]byte(parts[1]),
				[]byte(token),
			) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, apiResponse{
				Status: "UNAUTHORIZED",
				Error:  "Missing or invalid bearer token",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func fabricHealthHandler(
	check func(context.Context) error,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		if err := check(ctx); err != nil {
			log.Printf("Fabric readiness check failed: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "UNAVAILABLE",
				"mode":   "FABRIC_GATEWAY_READ_WRITE",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ONLINE",
			"mode":   "FABRIC_GATEWAY_READ_WRITE",
			"fabric": "READY",
		})
	}
}

func main() {
	authToken := strings.TrimSpace(os.Getenv("FABRIC_GATEWAY_TOKEN"))
	if len(authToken) < 32 {
		log.Fatal("FABRIC_GATEWAY_TOKEN must be configured with at least 32 characters")
	}

	listenAddr := requiredEnv(
		"FABRIC_GATEWAY_LISTEN_ADDR",
		"127.0.0.1:8090",
	)
	peerEndpoint := requiredEnv(
		"FABRIC_PEER_ENDPOINT",
		"localhost:7051",
	)
	tlsServerName := requiredEnv(
		"FABRIC_TLS_SERVER_NAME",
		"peer0.org1.agenttrust.com",
	)
	root := requiredEnv(
		"FABRIC_CRYPTO_PATH",
		filepath.Join("..", "crypto-config"),
	)

	identityDir := requiredEnv(
		"FABRIC_IDENTITY_CERT_DIR",
		filepath.Join(
			root, "peerOrganizations", "org1.agenttrust.com",
			"users", "Admin@org1.agenttrust.com", "msp", "signcerts",
		),
	)

	keyDir := requiredEnv(
		"FABRIC_IDENTITY_KEY_DIR",
		filepath.Join(
			root, "peerOrganizations", "org1.agenttrust.com",
			"users", "Admin@org1.agenttrust.com", "msp", "keystore",
		),
	)

	tlsCertPath := requiredEnv(
		"FABRIC_PEER_TLS_CA_PATH",
		filepath.Join(
			root, "peerOrganizations", "org1.agenttrust.com",
			"peers", "peer0.org1.agenttrust.com", "tls", "ca.crt",
		),
	)

	certPath, err := firstFile(identityDir)
	if err != nil {
		log.Fatal("identity certificate: ", err)
	}
	keyPath, err := firstFile(keyDir)
	if err != nil {
		log.Fatal("identity private key: ", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatal("read identity certificate: ", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		log.Fatal("parse identity certificate: ", err)
	}
	id, err := identity.NewX509Identity("Org1MSP", cert)
	if err != nil {
		log.Fatal("create X509 identity: ", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatal("read identity private key: ", err)
	}
	key, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		log.Fatal("parse identity private key: ", err)
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		log.Fatal("create signer: ", err)
	}

	caPEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		log.Fatal("read peer TLS CA: ", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("peer TLS CA contains no valid certificates")
	}

	tlsCredentials := credentials.NewTLS(&tls.Config{
		RootCAs:    certPool,
		ServerName: tlsServerName,
		MinVersion: tls.VersionTLS12,
	})

	connection, err := grpc.NewClient(
		peerEndpoint,
		grpc.WithTransportCredentials(tlsCredentials),
	)
	if err != nil {
		log.Fatal("create Gateway connection: ", err)
	}
	defer connection.Close()

	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(connection),
	)
	if err != nil {
		log.Fatal("connect to Fabric Gateway: ", err)
	}
	defer gateway.Close()

	channelName, chaincodeName := gatewayContractNames()
	contract := gateway.GetNetwork(channelName).GetContract(chaincodeName)
	log.Println("Connected to Fabric Gateway; read/write API starting")

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", fabricHealthHandler(
		func(ctx context.Context) error {
			_, err := contract.EvaluateWithContext(
				ctx,
				"VerifyEvidenceReference",
				client.WithArguments(
					"__agenttrust_health_probe__",
					"__agenttrust_probe_hash__",
				),
			)
			return err
		},
	))

	mux.HandleFunc("POST /v1/action-events", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
		defer r.Body.Close()

		type actionEventRequest struct {
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
		}

		var request actionEventRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{
				Status: "INVALID_REQUEST", Error: "Expected valid JSON request",
			})
			return
		}

		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, apiResponse{
				Status: "INVALID_REQUEST", Error: "Request must contain one JSON object",
			})
			return
		}

		fields := []string{
			request.EventID, request.RequestID, request.AgentID,
			request.Action, request.Resource, request.Decision,
			request.Reason, request.PolicyID, request.PolicyVersion,
			request.EvidenceReference, request.EvidenceHash,
		}
		for _, field := range fields {
			if field == "" {
				writeJSON(w, http.StatusBadRequest, apiResponse{
					Status: "INVALID_REQUEST", Error: "All action-event fields are required",
				})
				return
			}
		}

		// Fabric Gateway's SubmitTransaction waits for the transaction commit
		// status. A returned error is not assumed to mean the transaction was
		// definitely uncommitted; the caller must reconcile uncertain outcomes.
		result, err := contract.SubmitTransaction(
			"RecordActionEvent",
			request.EventID,
			request.RequestID,
			request.AgentID,
			request.Action,
			request.Resource,
			request.Decision,
			request.Reason,
			request.PolicyID,
			request.PolicyVersion,
			request.EvidenceReference,
			request.EvidenceHash,
		)
		if err != nil {
			log.Printf("Fabric action-event submission outcome may require reconciliation: %v", err)
			writeJSON(w, http.StatusBadGateway, apiResponse{
				Status: "FABRIC_SUBMISSION_UNCERTAIN",
				Error:  "Fabric transaction was not confirmed; reconcile event_id before retrying",
			})
			return
		}

		if !json.Valid(result) {
			// The transaction may already have committed. Do not suggest that
			// retrying the write is safe merely because its response was invalid.
			writeJSON(w, http.StatusBadGateway, apiResponse{
				Status: "COMMIT_RESULT_UNPARSEABLE",
				Error:  "Fabric returned an unparseable transaction result; reconcile event_id",
			})
			return
		}

		writeJSON(w, http.StatusOK, apiResponse{
			Status: "COMMITTED",
			Result: json.RawMessage(result),
		})
	})

	mux.HandleFunc("GET /v1/action-events/{event_id}", func(w http.ResponseWriter, r *http.Request) {
		eventID := r.PathValue("event_id")
		if eventID == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{
				Status: "INVALID_REQUEST",
				Error:  "A valid event_id path parameter is required",
			})
			return
		}

		result, err := contract.EvaluateTransaction("GetActionEvent", eventID)
		if err != nil {
			log.Printf("Fabric action-event query failed for event_id %q: %v", eventID, err)
			writeJSON(w, http.StatusBadGateway, apiResponse{
				Status: "FABRIC_QUERY_FAILED",
				Error:  "Fabric Gateway could not confirm the action-event state",
			})
			return
		}

		if !json.Valid(result) {
			writeJSON(w, http.StatusBadGateway, apiResponse{
				Status: "INVALID_CHAINCODE_RESPONSE",
				Error:  "Chaincode returned invalid JSON",
			})
			return
		}

		writeJSON(w, http.StatusOK, apiResponse{
			Status: "FOUND",
			Result: json.RawMessage(result),
		})
	})

	mux.HandleFunc("POST /v1/evidence/verify", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		defer r.Body.Close()

		var request verifyRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{
				Status: "INVALID_REQUEST", Error: "Expected valid JSON request",
			})
			return
		}

		if request.EvidenceRef == "" || request.ExpectedHash == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{
				Status: "INVALID_REQUEST",
				Error:  "evidence_ref and expected_hash are required",
			})
			return
		}

		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, apiResponse{
				Status: "INVALID_REQUEST", Error: "Request must contain one JSON object",
			})
			return
		}

		result, err := contract.EvaluateTransaction(
			"VerifyEvidenceReference",
			request.EvidenceRef,
			request.ExpectedHash,
		)
		if err != nil {
			log.Printf("Fabric query failed: %v", err)
			writeJSON(w, http.StatusBadGateway, apiResponse{
				Status: "FABRIC_QUERY_FAILED",
				Error:  "Fabric Gateway query failed",
			})
			return
		}

		if !json.Valid(result) {
			writeJSON(w, http.StatusBadGateway, apiResponse{
				Status: "INVALID_CHAINCODE_RESPONSE",
				Error:  "Chaincode returned invalid JSON",
			})
			return
		}

		writeJSON(w, http.StatusOK, apiResponse{
			Status: "SUCCESS",
			Result: json.RawMessage(result),
		})
	})

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal("listen on "+listenAddr+": ", err)
	}

	server := &http.Server{
		Handler:           bearerAuth(authToken, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return context.Background()
		},
	}

	log.Printf("Listening on %s", listenAddr)
	if err := server.Serve(listener); err != nil &&
		err != http.ErrServerClosed {
		log.Fatal("HTTP server: ", err)
	}
}
