package main

import (
	"context"
	"net/http"

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

	// Initialize Watson client
	var err error
	watsonClient, err = ai.NewDefaultWatsonClient()
	if err != nil {
		logger.Fatal("Failed to initialize Watson client: %v", err)
	}
	logger.Info("✅ Watson AI client initialized")

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
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "ai-core",
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
	RecommendedAction string        `json:"recommended_action"`
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

	// Call Watson AI
	aiReq := ai.AIRequest{
		EventType: evt.Type,
		Message:   evt.Message,
	}

	result, err := watsonClient.Analyze(aiReq)
	if err != nil {
		logger.Error("AI processing failed: %v", err)
		// Return fallback response
		c.JSON(http.StatusOK, AIResponse{
			Severity:          "unknown",
			Explanation:       "AI processing failed: " + err.Error(),
			RecommendedAction: "Check AI service or logs",
		})
		return
	}

	response := AIResponse{
		Severity:          result.Severity,
		Explanation:       result.Explanation,
		RecommendedAction: result.RecommendedAction,
	}

	// Optionally forward enriched event to API Gateway
	forwardToGateway := config.GetEnvBool("FORWARD_TO_GATEWAY", true)
	if forwardToGateway && gatewayClient != nil {
		go forwardToAPIGateway(evt, result)
	}

	logger.Info("AI processing successful: severity=%s", result.Severity)
	c.JSON(http.StatusOK, response)
}

// forwardToAPIGateway sends the enriched event to API Gateway
func forwardToAPIGateway(event EventRequest, aiResult *ai.AIResponse) {
	enrichedEvent := map[string]interface{}{
		"type":        event.Type,
		"message":     event.Message,
		"source_host": event.SourceHost,
		"source_ip":   event.SourceIP,
		"event_type":  event.EventType,
		"category":    event.Category,
		"severity":    aiResult.Severity,
		"ai_analysis": map[string]string{
			"severity":           aiResult.Severity,
			"explanation":        aiResult.Explanation,
			"recommended_action": aiResult.RecommendedAction,
		},
	}

	ctx := context.Background()
	resp, err := gatewayClient.Post(ctx, "/api/internal/events", enrichedEvent, nil)
	if err != nil {
		logger.Error("Failed to forward to API Gateway: %v", err)
		return
	}

	if !resp.IsSuccess() {
		logger.Warn("API Gateway returned non-success: %d", resp.StatusCode)
	} else {
		logger.Debug("Event forwarded to API Gateway successfully")
	}
}
