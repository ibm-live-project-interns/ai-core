package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ibm-live-project-interns/ai-core/ai"
	"github.com/ibm-live-project-interns/ingestor/shared/config"
	"github.com/ibm-live-project-interns/ingestor/shared/errors"
	"github.com/ibm-live-project-interns/ingestor/shared/httpclient"
	"github.com/ibm-live-project-interns/ingestor/shared/logger"
	"github.com/ibm-live-project-interns/ingestor/shared/middleware"
	"github.com/joho/godotenv"
)

var (
	watsonClient  *ai.WatsonClient
	gatewayClient *httpclient.Client
)

func main() {
	// Load env vars (non-fatal)
	if err := godotenv.Load(); err != nil {
		logger.Warn(".env not found, using environment variables")
	} else {
		logger.Info(".env loaded successfully")
	}

	// Initialize logger
	logCfg := logger.DefaultLoggerConfig()
	logCfg.ServiceName = "ai-core"
	logger.Init(logCfg)

	logger.Info("🚀 AI-Core starting...")

	// Initialize Watson client (non-fatal - runs in degraded mode without keys)
	var err error
	watsonClient, err = ai.NewDefaultWatsonClient()
	if err != nil {
		logger.Warn("Watson client not available: %v. AI Core will run in degraded mode.", err)
	} else {
		logger.Info("✅ Watson AI client initialized")
	}

	// Initialize API Gateway client for forwarding
	apiGatewayURL := config.GetEnv("API_GATEWAY_URL", "http://api-gateway:8080")
	gatewayClient = httpclient.NewClientWithBaseURL(apiGatewayURL)
	logger.Info("✅ API Gateway client initialized: %s", apiGatewayURL)

	// Setup Gin router
	gin.SetMode(config.GetEnv("GIN_MODE", "release"))
	router := gin.New()

	// Apply shared middleware
	router.Use(middleware.Recovery())
	router.Use(middleware.RequestLogger())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RateLimit())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		status := "healthy"
		if watsonClient == nil {
			status = "degraded"
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  status,
			"service": "ai-core",
			"watson":  watsonClient != nil,
		})
	})

	// Main AI processing endpoint
	router.POST("/events", handleEvent)

	// Start server
	port := config.GetEnv("AI_CORE_PORT", "9000")
	logger.Info("🚀 AI-Core running on :%s", port)
	if err := router.Run(":" + port); err != nil {
		logger.Fatal("❌ Failed to start AI-Core: %v", err)
	}
}

// EventRequest represents an incoming event
type EventRequest struct {
	Type       string `json:"type" binding:"required"`
	Message    string `json:"message" binding:"required"`
	SourceHost string `json:"source_host,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	EventType  string `json:"event_type,omitempty"`
	Category   string `json:"category,omitempty"`
	Severity   string `json:"severity,omitempty"`
}

// AIResponse represents the response from AI processing
type AIResponse struct {
	Severity          string        `json:"severity"`
	Explanation       string        `json:"explanation"`
	RootCause         string        `json:"root_cause"`
	Impact            string        `json:"impact"`
	RecommendedAction string        `json:"recommended_action"`
	Confidence        int           `json:"confidence,omitempty"`
	OriginalEvent     *EventRequest `json:"original_event,omitempty"`
}

func handleEvent(c *gin.Context) {
	var evt EventRequest

	if err := c.ShouldBindJSON(&evt); err != nil {
		apiErr := errors.NewValidation(err.Error())
		c.JSON(apiErr.HTTPStatus, apiErr.ToResponse())
		return
	}

	logger.Debug("Processing event: type=%s, message=%s", evt.Type, evt.Message)

	// Check if Watson client is available
	if watsonClient == nil {
		logger.Warn("Watson client not initialized - returning degraded response for event type=%s", evt.Type)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":              "AI service not configured",
			"detail":             "Watson API keys not provided",
			"fallback":           true,
			"severity":           evt.Severity,
			"explanation":        "AI processing unavailable - Watson API keys not configured",
			"recommended_action": "Configure WATSONX_API_KEYS environment variable",
		})
		return
	}

	// Call Watson AI
	aiReq := ai.AIRequest{
		EventType: evt.Type,
		Message:   evt.Message,
	}

	result, err := watsonClient.Analyze(aiReq)
	if err != nil {
		logger.Error("AI processing failed for event type=%s source=%s: %v", evt.Type, evt.SourceHost, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":    "AI processing failed",
			"detail":   err.Error(),
			"fallback": true,
			"severity":          "unknown",
			"explanation":       "AI processing unavailable - manual review required",
			"recommended_action": "Check AI service logs and Watson API connectivity",
		})
		return
	}

	response := AIResponse{
		Severity:          result.Severity,
		Explanation:       result.Explanation,
		RootCause:         result.RootCause,
		Impact:            result.Impact,
		RecommendedAction: result.RecommendedAction,
		Confidence:        result.Confidence,
	}

	// Optionally forward enriched event to API Gateway
	forwardToGateway := config.GetEnvBool("FORWARD_TO_GATEWAY", true)
	if forwardToGateway && gatewayClient != nil {
		go forwardToAPIGateway(evt, result)
	}

	logger.Info("AI processing successful: severity=%s", result.Severity)
	c.JSON(http.StatusOK, response)
}

// forwardToAPIGateway sends the enriched event to API Gateway with a timeout
func forwardToAPIGateway(event EventRequest, aiResult *ai.AIResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	enrichedEvent := map[string]interface{}{
		"type":        event.Type,
		"message":     event.Message,
		"source_host": event.SourceHost,
		"source_ip":   event.SourceIP,
		"event_type":  event.EventType,
		"category":    event.Category,
		"severity":    aiResult.Severity,
		"ai_analysis": map[string]interface{}{
			"severity":           aiResult.Severity,
			"explanation":        aiResult.Explanation,
			"root_cause":         aiResult.RootCause,
			"impact":             aiResult.Impact,
			"recommended_action": aiResult.RecommendedAction,
			"confidence":         float64(aiResult.Confidence),
		},
	}

	logger.Debug("Forwarding enriched event to API Gateway: type=%s severity=%s source=%s", event.Type, aiResult.Severity, event.SourceHost)

	resp, err := gatewayClient.Post(ctx, "/api/internal/events", enrichedEvent, nil)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("Timeout forwarding to API Gateway (10s): %v", err)
		} else {
			logger.Error("Failed to forward to API Gateway: %v", err)
		}
		return
	}

	if !resp.IsSuccess() {
		logger.Warn("API Gateway returned non-success status %d for event type=%s", resp.StatusCode, event.Type)
	} else {
		logger.Info("Event forwarded to API Gateway successfully: type=%s severity=%s", event.Type, aiResult.Severity)
	}
}
