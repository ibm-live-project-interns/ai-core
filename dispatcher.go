package main

func DispatchEvent(event Event) UnifiedResponse {

    Logger.Println("Dispatching event")

    relevantCVEs := FindRelevantCVEs(event.Message)

    response, err := CallWatsonAI(event, relevantCVEs)
    if err != nil {
        Logger.Printf("AI processing failed: %v", err)

        return UnifiedResponse{
            Severity:          "unknown",
            Explanation:       err.Error(),
            RecommendedAction: "Check logs",
        }
    }

    Logger.Println("AI processing successful")
    return response
}