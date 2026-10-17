package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// MCPRequest / MCPResponse represent JSON-RPC 2.0 message shapes.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPServer exposes OpenClaw sandbox as an MCP server.
type MCPServer struct {
	cfg       *Config
	defender  *Defender
	transport string // stdio or sse
}

func NewMCPServer(cfg *Config) *MCPServer {
	return &MCPServer{
		cfg:       cfg,
		defender:  NewDefender(cfg),
		transport: cfg.MCPTransport,
	}
}

func (s *MCPServer) Run(ctx context.Context) error {
	if s.transport == "sse" {
		return s.runSSE(ctx)
	}
	return s.runStdio(ctx)
}

func (s *MCPServer) runStdio(ctx context.Context) error {
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var req MCPRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.writeError(encoder, nil, -32700, "Parse error")
			continue
		}
		resp := s.handle(req)
		if resp != nil {
			encoder.Encode(resp)
		}
	}
}

func (s *MCPServer) runSSE(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req MCPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		resp := s.handle(req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	server := &http.Server{Addr: ":18080", Handler: mux}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()
	fmt.Fprintf(os.Stderr, "[MCP SSE] listening on http://localhost:18080/mcp\n")
	return server.ListenAndServe()
}

func (s *MCPServer) handle(req MCPRequest) *MCPResponse {
	switch req.Method {
	case "initialize":
		return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"serverInfo": map[string]interface{}{
				"name":    "tarsclaw-sandbox",
				"version": "0.1.0",
			},
		}}
	case "tools/list":
		return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"tools": []map[string]interface{}{
				{"name": "sandbox_up", "description": "Start OpenClaw inside sandbox", "inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"mode": map[string]interface{}{"type": "string", "enum": []string{"docker-compat", "gvisor", "firecracker"}}}}},
				{"name": "sandbox_down", "description": "Stop sandboxed OpenClaw"},
				{"name": "defender_status", "description": "List active defenses"},
				{"name": "filter_llm", "description": "Filter prompt through injection guard", "inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"prompt": map[string]interface{}{"type": "string"}}}},
				{"name": "check_ssrf", "description": "Check URL against SSRF blacklist", "inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"url": map[string]interface{}{"type": "string"}}}},
			},
		}}
	case "tools/call":
		return s.handleToolCall(req)
	default:
		return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Error: &MCPError{Code: -32601, Message: "Method not found"}}
	}
}

func (s *MCPServer) handleToolCall(req MCPRequest) *MCPResponse {
	var params struct {
		Name string                 `json:"name"`
		Args map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Error: &MCPError{Code: -32602, Message: "Invalid params"}}
	}
	var result interface{}
	switch params.Name {
	case "sandbox_up":
		mode, _ := params.Args["mode"].(string)
		if mode == "" {
			mode = s.cfg.SandboxMode
		}
		result = map[string]string{"status": "started", "mode": mode}
	case "sandbox_down":
		result = map[string]string{"status": "stopped"}
	case "defender_status":
		result = map[string]interface{}{
			"plugin_isolation":     s.cfg.PluginIsolation,
			"token_encryption":     s.cfg.TokenEncryption,
			"webhook_ssrf_block":   s.cfg.WebhookSSRFBlock,
			"llm_filter":           s.cfg.LLMFilter,
			"oauth_csrf":           s.cfg.OAuthCSRF,
			"im_smuggling_block":   s.cfg.IMSmugglingBlock,
			"path_traversal_guard": s.cfg.PathTraversalGuard,
			"websocket_cswsh":      s.cfg.WebSocketCSWSHGuard,
		}
	case "filter_llm":
		prompt, _ := params.Args["prompt"].(string)
		filtered, err := s.defender.FilterLLM(prompt)
		if err != nil {
			result = map[string]string{"blocked": "true", "reason": err.Error()}
		} else {
			result = map[string]string{"blocked": "false", "output": filtered}
		}
	case "check_ssrf":
		u, _ := params.Args["url"].(string)
		if err := s.defender.BlockSSRF(u); err != nil {
			result = map[string]string{"blocked": "true", "reason": err.Error()}
		} else {
			result = map[string]string{"blocked": "false"}
		}
	default:
		return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Error: &MCPError{Code: -32602, Message: "Unknown tool"}}
	}
	return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *MCPServer) writeError(enc *json.Encoder, id interface{}, code int, msg string) {
	enc.Encode(&MCPResponse{JSONRPC: "2.0", ID: id, Error: &MCPError{Code: code, Message: msg}})
}
