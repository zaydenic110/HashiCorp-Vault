package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const successHTML = `
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Vault OIDC Login</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			background-color: #f5f5f7;
			color: #1d1d1f;
			display: flex;
			justify-content: center;
			align-items: center;
			height: 100vh;
			margin: 0;
		}
		.container {
			background-color: #ffffff;
			padding: 40px;
			border-radius: 12px;
			box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
			text-align: center;
			max-width: 400px;
		}
		h1 {
			font-size: 24px;
			margin-bottom: 16px;
		}
		p {
			font-size: 16px;
			line-height: 1.5;
			color: #86868b;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>Authenticated!</h1>
		<p>You have successfully authenticated. You can now close this window and return to the CLI.</p>
		</div>
</body>
</html>
`

type cliHandler struct {
	state string
	code  string
	err   error
	ch    chan struct{}
	once  sync.Once
}

func (h *cliHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/oidc/callback" {
		http.NotFound(w, r)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if strings.Contains(code, "%") {
		if decoded, err := url.QueryUnescape(code); err == nil {
			code = decoded
		}
	}
	if strings.Contains(state, "%") {
		if decoded, err := url.QueryUnescape(state); err == nil {
			state = decoded
		}
	}

	if code == "" {
		h.err = fmt.Errorf("missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		h.close()
		return
	}

	if state == "" {
		h.err = fmt.Errorf("missing state")
		http.Error(w, "Missing state", http.StatusBadRequest)
		h.close()
		return
	}

	if state != h.state {
		h.err = fmt.Errorf("state mismatch")
		http.Error(w, "State mismatch", http.StatusBadRequest)
		h.close()
		return
	}

	h.code = code
	h.close()

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(successHTML))
}

func (h *cliHandler) close() {
	h.once.Do(func() {
		close(h.ch)
	})
}

// GetOIDCAuthCode starts a local server to receive the OIDC callback.
// It returns the authorization code.
func GetOIDCAuthCode(ctx context.Context, port int, state string, timeout time.Duration) (string, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}
	defer listener.Close()

	ch := make(chan struct{})
	handler := &cliHandler{
		state: state,
		ch:    ch,
	}

	server := &http.Server{
		Handler: handler,
	}

	go func() {
		server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		server.Shutdown(context.Background())
		return "", ctx.Err()
	case <-time.After(timeout):
		server.Shutdown(context.Background())
		return "", fmt.Errorf("timeout waiting for OIDC callback")
	case <-ch:
		server.Shutdown(context.Background())
		return handler.code, handler.err
	}
}
