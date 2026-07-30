package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCLIHandler(t *testing.T) {
	tests := []struct {
		name           string
		state          string
		query          string
		expectedCode   string
		expectedStatus int
		expectedErr    string
	}{
		{
			name:           "success",
			state:          "state123",
			query:          "?code=code123&state=state123",
			expectedCode:   "code123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing code",
			state:          "state123",
			query:          "?state=state123",
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "missing authorization code",
		},
		{
			name:           "missing state",
			state:          "state123",
			query:          "?code=code123",
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "missing state",
		},
		{
			name:           "state mismatch",
			state:          "state123",
			query:          "?code=code123&state=state456",
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "state mismatch",
		},
		{
			name:           "double-encoded success",
			state:          "state123",
			query:          "?code=code123%253D%253D&state=state123",
			expectedCode:   "code123==",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "double-encoded state success",
			state:          "state123==",
			query:          "?code=code123&state=state123%253D%253D",
			expectedCode:   "code123",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan struct{})
			handler := &cliHandler{
				state: tc.state,
				ch:    ch,
			}

			req := httptest.NewRequest("GET", "/oidc/callback"+tc.query, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, w.Code)
			}

			if tc.expectedErr != "" {
				if handler.err == nil || handler.err.Error() != tc.expectedErr {
					t.Errorf("expected error %q, got %v", tc.expectedErr, handler.err)
				}
			} else {
				if handler.err != nil {
					t.Errorf("unexpected error: %v", handler.err)
				}
				if handler.code != tc.expectedCode {
					t.Errorf("expected code %q, got %q", tc.expectedCode, handler.code)
				}
			}
		})
	}
}
