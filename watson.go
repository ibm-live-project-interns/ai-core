package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

/* ---------------- API KEY ROTATION ---------------- */

var (
	apiKeys  []string
	keyIndex int
	keyMutex sync.Mutex
)

func getNextAPIKey() (string, error) {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	if len(apiKeys) == 0 {
		raw := os.Getenv("WATSONX_API_KEYS")
		if raw == "" {
			return "", errors.New("WATSONX_API_KEYS not set")
		}
		apiKeys = strings.Split(raw, ",")
	}

	key := apiKeys[keyIndex]
	keyIndex = (keyIndex + 1) % len(apiKeys)
	return key, nil
}

/* ---------------- IAM TOKEN CACHE (PER KEY) ---------------- */

type tokenEntry struct {
	token  string
	expiry time.Time
}

var (
	tokenCache = map[string]tokenEntry{}
	tokenMutex sync.Mutex
)

func getIAMToken(apiKey string) (string, error) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	if entry, ok := tokenCache[apiKey]; ok {
		if time.Now().Before(entry.expiry) {
			return entry.token, nil
		}
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", apiKey)

	req, err := http.NewRequest(
		"POST",
		"https://iam.cloud.ibm.com/identity/token",
		bytes.NewBufferString(data.Encode()),
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("IAM auth failed %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	tokenCache[apiKey] = tokenEntry{
		token:  tokenResp.AccessToken,
		expiry: time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second),
	}

	return tokenResp.AccessToken, nil
}

/* ---------------- SAFE JSON EXTRACTOR ---------------- */

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

/* ---------------- CALL WATSONX ---------------- */

func CallWatsonAI(event Event) (UnifiedResponse, error) {
	apiKey, err := getNextAPIKey()
	if err != nil {
		return UnifiedResponse{}, err
	}

	region := os.Getenv("WATSONX_REGION")
	projectID := os.Getenv("WATSONX_PROJECT_ID")

	if region == "" || projectID == "" {
		return UnifiedResponse{}, errors.New("Watsonx env vars missing")
	}

	Logger.Println("🔐 Fetching IAM token")
	token, err := getIAMToken(apiKey)
	if err != nil {
		return UnifiedResponse{}, err
	}

	endpoint := fmt.Sprintf(
		"https://%s.ml.cloud.ibm.com/ml/v1/text/generation?version=2024-01-10",
		region,
	)

	prompt := fmt.Sprintf(
		`<System data>
Event type: %s
Event message: %s
</System data>

<Instructions>
Use the system data to answer the question.
Do NOT mention system data.
Respond ONLY in valid JSON with fields:
severity, explanation, recommended_action.
</Instructions>

<Question>
What is the severity and recommended action?
</Question>`,
		event.Type,
		event.Message,
	)

	payload := map[string]interface{}{
		"model_id":   "ibm/granite-3-8b-instruct",
		"project_id": projectID,
		"input":      prompt,
		"parameters": map[string]interface{}{
			"temperature":    0.1,
			"max_new_tokens": 120,
			"stop": []string{
				"\n\nType:",
				"\n\nMessage:",
				"</System data>",
			},
		},
	}

	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return UnifiedResponse{}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	Logger.Println("🤖 Calling Watsonx model")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return UnifiedResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return UnifiedResponse{}, fmt.Errorf("Watsonx failed %d: %s", resp.StatusCode, string(body))
	}

	var res struct {
		Results []struct {
			GeneratedText string `json:"generated_text"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return UnifiedResponse{}, err
	}

	if len(res.Results) == 0 {
		return UnifiedResponse{}, errors.New("empty response from Watsonx")
	}

	cleanJSON := extractFirstJSON(res.Results[0].GeneratedText)
	if cleanJSON == "" {
		return UnifiedResponse{
			Severity:          "unknown",
			Explanation:       res.Results[0].GeneratedText,
			RecommendedAction: "Manual review required",
		}, nil
	}

	var ai UnifiedResponse
	if err := json.Unmarshal([]byte(cleanJSON), &ai); err != nil {
		return UnifiedResponse{
			Severity:          "unknown",
			Explanation:       cleanJSON,
			RecommendedAction: "Manual review required",
		}, nil
	}

	Logger.Println("✅ Watsonx response parsed successfully")
	return ai, nil
}
