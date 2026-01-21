package main

import (
	"log"
	"os"
)

var Logger *log.Logger

func InitLogger() {
	// Create logs directory if not exists
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		_ = os.Mkdir("logs", 0755)
	}

	logFile, err := os.OpenFile(
		"logs/agents_api.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	Logger = log.New(
		logFile,
		"[AGENTS_API] ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)

	Logger.Println("Logger initialized")
}
