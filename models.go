package main

type Event struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type UnifiedResponse struct {
	Severity          string `json:"severity"`
	Explanation       string `json:"explanation"`
	RecommendedAction string `json:"recommended_action"`
}
