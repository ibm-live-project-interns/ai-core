package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	println("🔥🔥 THIS IS AI-CORE MAIN.GO 🔥🔥")


	// Load env vars (non-fatal)
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  .env not found, using environment variables")
	} else {
		log.Println("✅ .env loaded successfully")
	}

	// Init logger
	InitLogger()
	Logger.Println("🚀 Agents API starting")

	router := gin.Default()

	router.POST("/events", func(c *gin.Context) {
		var evt Event

		if err := c.ShouldBindJSON(&evt); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result := DispatchEvent(evt)
		c.JSON(http.StatusOK, result)
	})

	Logger.Println("🚀 Agents API running on :9000")
	if err := router.Run(":9000"); err != nil {
		Logger.Fatal("❌ Failed to start Agents API:", err)
	}
}
