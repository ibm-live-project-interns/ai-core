package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ibm-live-project-interns/ingestor/shared/config"
	"github.com/ibm-live-project-interns/ingestor/shared/errors"
	"github.com/ibm-live-project-interns/ingestor/shared/logger"
)

// WatsonConfig holds Watson AI configuration
type WatsonConfig struct {
	// API keys (comma-separated for rotation)
	APIKeys []string
	// Region (e.g., us-south)
	Region string
	// Project ID
	ProjectID string
	// Model ID
	ModelID string
	// Request timeout
	Timeout time.Duration
	// Temperature for generation (0.0 - 1.0)
	Temperature float64
	// Max tokens to generate
	MaxNewTokens int
	// IAM Token URL
	IAMTokenURL string
	// API Version
	APIVersion string
}

// DefaultWatsonConfig returns default Watson configuration
func DefaultWatsonConfig() WatsonConfig {
	apiKeysStr := config.GetEnv("WATSONX_API_KEYS", config.GetEnv("WATSONX_API_KEY", ""))
	var apiKeys []string
	if apiKeysStr != "" {
		apiKeys = strings.Split(apiKeysStr, ",")
	}

	// Parse temperature from env (default 0.1)
	temperature := 0.1
	if tempStr := config.GetEnv("WATSONX_TEMPERATURE", ""); tempStr != "" {
		if t, err := parseFloat(tempStr); err == nil && t >= 0 && t <= 1 {
			temperature = t
		}
	}

	return WatsonConfig{
		APIKeys:      apiKeys,
		Region:       config.GetEnv("WATSONX_REGION", "us-south"),
		ProjectID:    config.GetEnv("WATSONX_PROJECT_ID", ""),
		ModelID:      config.GetEnv("WATSONX_MODEL_ID", "ibm/granite-3-8b-instruct"),
		Timeout:      time.Duration(config.GetEnvInt("WATSONX_TIMEOUT_SECONDS", 30)) * time.Second,
		Temperature:  temperature,
		MaxNewTokens: config.GetEnvInt("WATSONX_MAX_NEW_TOKENS", 200),
		IAMTokenURL:  config.GetEnv("IBM_IAM_TOKEN_URL", "https://iam.cloud.ibm.com/identity/token"),
		APIVersion:   config.GetEnv("WATSONX_API_VERSION", "2024-01-10"),
	}
}

// parseFloat parses a string to float64
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// WatsonClient is a client for IBM Watson AI
type WatsonClient struct {
	config     WatsonConfig
	httpClient *http.Client

	// API key rotation
	keyIndex int
	keyMutex sync.Mutex

	// Token cache per API key
	tokenCache map[string]tokenEntry
	tokenMutex sync.Mutex
}

type tokenEntry struct {
	token  string
	expiry time.Time
}

// NewWatsonClient creates a new Watson client
func NewWatsonClient(cfg WatsonConfig) (*WatsonClient, error) {
	if len(cfg.APIKeys) == 0 {
		return nil, errors.NewInternal("No Watson API keys configured")
	}
	if cfg.Region == "" {
		return nil, errors.NewInternal("Watson region not configured")
	}
	if cfg.ProjectID == "" {
		return nil, errors.NewInternal("Watson project ID not configured")
	}

	return &WatsonClient{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		tokenCache: make(map[string]tokenEntry),
	}, nil
}

// NewDefaultWatsonClient creates a client with default configuration
func NewDefaultWatsonClient() (*WatsonClient, error) {
	return NewWatsonClient(DefaultWatsonConfig())
}

// getNextAPIKey returns the next API key in rotation
func (c *WatsonClient) getNextAPIKey() string {
	c.keyMutex.Lock()
	defer c.keyMutex.Unlock()

	key := c.config.APIKeys[c.keyIndex]
	c.keyIndex = (c.keyIndex + 1) % len(c.config.APIKeys)
	return key
}

// getIAMToken gets or refreshes an IAM token
func (c *WatsonClient) getIAMToken(apiKey string) (string, error) {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	// Check cache
	if entry, ok := c.tokenCache[apiKey]; ok {
		if time.Now().Before(entry.expiry) {
			return entry.token, nil
		}
	}

	// Request new token
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", apiKey)

	req, err := http.NewRequest(
		"POST",
		c.config.IAMTokenURL,
		bytes.NewBufferString(data.Encode()),
	)
	if err != nil {
		return "", errors.NewAIProcessingError("failed to create IAM request", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", errors.NewAIProcessingError("IAM request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.NewAIProcessingError(
			fmt.Sprintf("IAM auth failed with status %d", resp.StatusCode),
			fmt.Errorf("%s", body),
		)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", errors.NewAIProcessingError("failed to decode IAM response", err)
	}

	// Cache token (expire 60s early for safety)
	c.tokenCache[apiKey] = tokenEntry{
		token:  tokenResp.AccessToken,
		expiry: time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second),
	}

	return tokenResp.AccessToken, nil
}

// AIRequest represents an AI analysis request
type AIRequest struct {
	EventType string `json:"event_type"`
	Message   string `json:"message"`
	Context   string `json:"context,omitempty"`
}

// AIResponse represents an AI analysis response
type AIResponse struct {
	Severity          string `json:"severity"`
	Explanation       string `json:"explanation"`
	RecommendedAction string `json:"recommended_action"`
	Confidence        int    `json:"confidence,omitempty"`
}

// Analyze sends an event to Watson for AI analysis
func (c *WatsonClient) Analyze(req AIRequest) (*AIResponse, error) {
	apiKey := c.getNextAPIKey()

	logger.Debug("Fetching IAM token for Watson AI")
	token, err := c.getIAMToken(apiKey)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf(
		"https://%s.ml.cloud.ibm.com/ml/v1/text/generation?version=%s",
		c.config.Region,
		c.config.APIVersion,
	)

	// Build prompt
	prompt := c.buildPrompt(req)

	payload := map[string]interface{}{
		"model_id":   c.config.ModelID,
		"project_id": c.config.ProjectID,
		"input":      prompt,
		"parameters": map[string]interface{}{
			"temperature":    c.config.Temperature,
			"max_new_tokens": c.config.MaxNewTokens,
			"stop":           []string{"\n\nType:", "\n\nMessage:", "</System data>"},
		},
	}

	body, _ := json.Marshal(payload)

	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.NewAIProcessingError("failed to create Watson request", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	logger.Debug("Calling Watson AI model: %s", c.config.ModelID)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, errors.NewAIProcessingError("Watson request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, errors.NewAIProcessingError(
			fmt.Sprintf("Watson returned status %d", resp.StatusCode),
			fmt.Errorf("%s", bodyBytes),
		)
	}

	var watsonResp struct {
		Results []struct {
			GeneratedText string `json:"generated_text"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&watsonResp); err != nil {
		return nil, errors.NewAIProcessingError("failed to decode Watson response", err)
	}

	if len(watsonResp.Results) == 0 {
		return nil, errors.NewAIProcessingError("empty response from Watson", nil)
	}

	// Parse AI response
	return c.parseResponse(watsonResp.Results[0].GeneratedText)
}

// buildPrompt creates the prompt for Watson
func (c *WatsonClient) buildPrompt(req AIRequest) string {
	contextPart := ""
	if req.Context != "" {
		contextPart = fmt.Sprintf("\nAdditional context: %s", req.Context)
	}

	return fmt.Sprintf(`<System data>
Event type: %s
Event message: %s%s
</System data>

<Instructions>
Use the system data to answer the question.
Do NOT mention system data or how you derived the answer.
Respond ONLY in valid JSON with fields:
severity (critical/high/medium/low/info), explanation, recommended_action.
</Instructions>

<Question>
What is the severity of the event and what action should be taken?
</Question>`,
		req.EventType,
		req.Message,
		contextPart,
	)
}

// parseResponse parses the Watson AI response
func (c *WatsonClient) parseResponse(text string) (*AIResponse, error) {
	// Extract JSON from response
	cleanJSON := extractFirstJSON(text)
	if cleanJSON == "" {
		return &AIResponse{
			Severity:          "unknown",
			Explanation:       text,
			RecommendedAction: "Manual review required",
		}, nil
	}

	var response AIResponse
	if err := json.Unmarshal([]byte(cleanJSON), &response); err != nil {
		return &AIResponse{
			Severity:          "unknown",
			Explanation:       cleanJSON,
			RecommendedAction: "Manual review required",
		}, nil
	}

	logger.Debug("Watson AI response parsed successfully: severity=%s", response.Severity)
	return &response, nil
}

// extractFirstJSON extracts the first valid JSON object from text
func extractFirstJSON(text string) string {
	start := strings.Index(text, "{")
	if start == -1 {
		return ""
	}

	braces := 0
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '{':
			braces++
		case '}':
			braces--
			if braces == 0 {
				return text[start : i+1]
			}
		}
	}
	return ""
}
