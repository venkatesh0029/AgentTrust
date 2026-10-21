package main

import (
	"context"
	"errors"
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

func TestClassifyActionEventQueryError(t *testing.T) {
	const eventID = "EVENT-TEST-123"

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name: "definitively missing event",
			err: errors.New(
				"rpc error: code = Unknown desc = " +
					"chaincode response 500, action event '" +
					eventID + "' not found",
			),
			wantStatus: http.StatusNotFound,
			wantBody:   "NOT_FOUND",
		},
		{
			name:       "peer connectivity failure stays uncertain",
			err:        errors.New("rpc error: code = Unavailable"),
			wantStatus: http.StatusBadGateway,
			wantBody:   "FABRIC_QUERY_FAILED",
		},
		{
			name:       "unrelated chaincode error stays uncertain",
			err:        errors.New("failed to read action event"),
			wantStatus: http.StatusBadGateway,
			wantBody:   "FABRIC_QUERY_FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, response := classifyActionEventQueryError(
				eventID,
				tt.err,
			)

			if status != tt.wantStatus {
				t.Fatalf(
					"got HTTP status %d, want %d",
					status,
					tt.wantStatus,
				)
			}

			if response.Status != tt.wantBody {
				t.Fatalf(
					"got response status %q, want %q",
					response.Status,
					tt.wantBody,
				)
			}
		})
	}
}

func TestClassifyActionEventSubmissionError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name: "known endorsement planning failure",
			err: errors.New(
				"endorse error: rpc error: code = FailedPrecondition desc = " +
					"no combination of peers can be derived which satisfy the endorsement policy: " +
					"no peer combination can satisfy the endorsement policy",
			),
			wantStatus: http.StatusConflict,
			wantBody:   "FABRIC_PRE_SUBMISSION_FAILURE",
		},
		{
			name:       "commit outcome remains uncertain",
			err:        errors.New("context deadline exceeded"),
			wantStatus: http.StatusBadGateway,
			wantBody:   "FABRIC_SUBMISSION_UNCERTAIN",
		},
		{
			name:       "unrecognized submission error remains uncertain",
			err:        errors.New("transaction status could not be confirmed"),
			wantStatus: http.StatusBadGateway,
			wantBody:   "FABRIC_SUBMISSION_UNCERTAIN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, response := classifyActionEventSubmissionError(tt.err)

			if status != tt.wantStatus {
				t.Fatalf("got HTTP status %d, want %d", status, tt.wantStatus)
			}
			if response.Status != tt.wantBody {
				t.Fatalf("got response status %q, want %q", response.Status, tt.wantBody)
			}
		})
	}
}
