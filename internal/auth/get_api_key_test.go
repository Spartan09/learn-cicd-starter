package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed header missing key",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "wrong scheme",
			headers:    http.Header{"Authorization": []string{"Bearer sometoken"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if tc.wantErrMsg != "" {
				if err == nil || err.Error() != tc.wantErrMsg {
					t.Errorf("got err %v, want %q", err, tc.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantKey {
				t.Errorf("got key %q, want %q", got, tc.wantKey)
			}
		})
	}
}
