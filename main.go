package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	fmt.Println("🔥🔥 AI-CORE STARTING 🔥🔥")

	/* ---------------- LOAD ENV ---------------- */

	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ .env not found — using system environment")
	} else {
		log.Println("✅ .env loaded")
	}

	/* ---------------- INIT LOGGER ---------------- */

	InitLogger()
	Logger.Println("🚀 Agents API starting")

	/* =========================================================
	   FORCE CVE INITIALIZATION (CRITICAL)
	   ========================================================= */

	Logger.Println("🌐 Initializing CVE cache...")

	err := EnsureRecentNetworkCVEs()

	if err != nil {
		Logger.Printf("❌ CVE initialization FAILED: %v", err)
	} else {
		Logger.Println("✅ CVE cache initialized successfully")
	}

	/* =========================================================
	   BACKGROUND REFRESH LOOP
	   Checks every 5 minutes
	   Fetch occurs only if cache is stale (≤15 min policy)
	   ========================================================= */

	go func() {

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {

			Logger.Println("🔄 Checking CVE cache freshness...")

			if err := EnsureRecentNetworkCVEs(); err != nil {
				Logger.Printf("⚠️ CVE refresh error: %v", err)
				continue
			}

			Logger.Println("✅ CVE cache check complete")
		}
	}()

	/* ---------------- GIN ROUTER ---------------- */

	router := gin.Default()

	router.POST("/events", func(c *gin.Context) {

		var evt Event

		if err := c.ShouldBindJSON(&evt); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		result := DispatchEvent(evt)
		c.JSON(http.StatusOK, result)
	})

	/* ---------------- START SERVER ---------------- */

	Logger.Println("🚀 Agents API running on :9000")

	if err := router.Run(":9000"); err != nil {
		Logger.Fatal("❌ Failed to start server:", err)
	}
}
