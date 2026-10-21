package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuthRejectsMissingAndInvalidTokens(t *testing.T) {
	const token = "test-token-for-authentication-123456"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := bearerAuth(token, next)

	tests := []struct {
		name          string
		authorization string
	}{
		{name: "missing token"},
		{name: "wrong token", authorization: "Bearer incorrect-token"},
		{name: "wrong scheme", authorization: "Basic " + token},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/action-events", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestBearerAuthAcceptsValidToken(t *testing.T) {
	const token = "test-token-for-authentication-123456"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := bearerAuth(token, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/action-events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestFabricHealthHandlerReportsUnavailable(t *testing.T) {
	handler := fabricHealthHandler(func(context.Context) error {
		return context.DeadlineExceeded
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), `"status":"UNAVAILABLE"`) {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}

func TestFabricHealthHandlerReportsReady(t *testing.T) {
	handler := fabricHealthHandler(func(context.Context) error {
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"fabric":"READY"`) {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}

func TestGatewayContractNamesDefaults(t *testing.T) {
	t.Setenv("FABRIC_CHANNEL_NAME", "")
	t.Setenv("FABRIC_CHAINCODE_NAME", "")

	channelName, chaincodeName := gatewayContractNames()

	if channelName != "agenttrust-channel" {
		t.Fatalf("unexpected channel name: %q", channelName)
	}
	if chaincodeName != "agenttrust" {
		t.Fatalf("unexpected chaincode name: %q", chaincodeName)
	}
}

func TestGatewayContractNamesConfigurable(t *testing.T) {
	t.Setenv("FABRIC_CHANNEL_NAME", "test-channel")
	t.Setenv("FABRIC_CHAINCODE_NAME", "test-chaincode")

	channelName, chaincodeName := gatewayContractNames()

	if channelName != "test-channel" {
		t.Fatalf("unexpected channel name: %q", channelName)
	}
	if chaincodeName != "test-chaincode" {
		t.Fatalf("unexpected chaincode name: %q", chaincodeName)
	}
}
