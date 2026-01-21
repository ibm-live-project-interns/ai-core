package main

type Event struct {
    Type     string `json:"type" binding:"required"`
    Message  string `json:"message" binding:"required"`
    Severity string `json:"severity,omitempty"`
}

type UnifiedResponse struct {
    Severity          string `json:"severity"`
    Explanation       string `json:"explanation"`
    RecommendedAction string `json:"recommended_action"`
}
