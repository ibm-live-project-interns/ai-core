package main

func DispatchEvent(event Event) UnifiedResponse {
	Logger.Println("Dispatching event to Watson AI")

	response, err := CallWatsonAI(event)
	if err != nil {
		Logger.Printf("AI processing failed: %v", err)

		return UnifiedResponse{
			Severity:          "unknown",
			Explanation:       "AI processing failed: " + err.Error(),
			RecommendedAction: "Check AI service or logs",
		}
	}

	Logger.Println("AI processing successful")
	return response
}
