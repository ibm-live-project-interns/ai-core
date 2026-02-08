# AI Core Service

AI-powered event analysis engine for the NOC Platform. Uses IBM Watson Granite 3-8B to classify network events by severity and recommend corrective actions.

## Architecture

```
Ingestor Pipeline → AI Core (:9000) → API Gateway (:8080) → UI
                      │
                      ├── POST /events    → Watson AI analysis
                      ├── GET  /health    → Service health check
                      │
                      └── ai/watson.go    → IBM Watson client
                          ├── IAM token management
                          ├── API key rotation
                          └── Prompt engineering
```

The AI Core receives events from the ingestor pipeline, sends them to IBM Watson for analysis, and forwards the enriched result (severity + explanation + recommended action) to the API Gateway.

## Quick Start

### Prerequisites

- Go 1.24+
- IBM Watson API credentials (see Environment Variables)
- API Gateway running at `http://localhost:8080`

### Run Locally

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your Watson credentials
# WATSONX_API_KEYS=your-key
# WATSONX_PROJECT_ID=your-project-id
# WATSONX_REGION=eu-gb

# Run the service
go run main.go
```

### Run with Docker

```bash
# Via infra orchestrator (recommended)
cd ../infra && python run_local.py

# Or build standalone (requires parent directory as context)
docker build -t ai-core -f ai-core/Dockerfile .
docker run -p 9000:9000 --env-file ai-core/.env ai-core
```

## API Endpoints

### POST /events

Process a network event through Watson AI analysis.

**Request:**
```json
{
  "type": "syslog",
  "message": "Interface GigabitEthernet0/1 changed state to down",
  "source_host": "router-01",
  "source_ip": "10.0.1.1"
}
```

**Response (200 OK):**
```json
{
  "severity": "critical",
  "explanation": "A network interface has gone down, which may cause connectivity loss for connected devices and services.",
  "recommended_action": "Check physical connection and interface configuration. Verify link partner status.",
  "original_event": { "..." }
}
```

**Error Responses:**
- `400` — Invalid request JSON
- `503` — Watson AI unavailable (missing credentials or service down)

### GET /health

Returns service health status including Watson AI availability.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WATSONX_API_KEYS` | Yes | — | Comma-separated IBM Watson API keys (supports rotation) |
| `WATSONX_PROJECT_ID` | Yes | — | IBM Watson project ID |
| `WATSONX_REGION` | No | `us-south` | IBM Cloud region (e.g. `eu-gb`) |
| `WATSONX_MODEL_ID` | No | `ibm/granite-3-8b-instruct` | Watson model ID |
| `WATSONX_TEMPERATURE` | No | `0.1` | Generation temperature (0.0-1.0) |
| `WATSONX_MAX_NEW_TOKENS` | No | `200` | Maximum response tokens |
| `WATSONX_TIMEOUT_SECONDS` | No | `30` | Watson API request timeout |
| `AI_CORE_PORT` | No | `9000` | Service port |
| `API_GATEWAY_URL` | No | `http://api-gateway:8080` | API Gateway URL for event forwarding |
| `FORWARD_TO_GATEWAY` | No | `true` | Enable forwarding enriched events |
| `LOG_LEVEL` | No | `info` | Log verbosity (debug, info, warn, error) |

## Watson AI Integration

The service communicates with IBM Watson via the watsonx.ai text generation API:

1. **IAM Authentication** — Exchanges API key for bearer token via `iam.cloud.ibm.com`
2. **Token Caching** — Tokens are cached per API key, refreshed 60s before expiry
3. **API Key Rotation** — Multiple keys are cycled sequentially for load balancing
4. **Prompt Engineering** — Structured prompt requests JSON response with severity, explanation, and recommended action
5. **Graceful Degradation** — Service starts in degraded mode if Watson credentials are missing, returns 503 instead of crashing

## Shared Dependencies

Uses `ingestor/shared` for common utilities:

```go
// go.mod
replace github.com/ibm-live-project-interns/ingestor/shared => ../ingestor/shared
```

Packages used: `config`, `errors`, `httpclient`, `logger`, `middleware`

## Project Structure

```
ai-core/
├── main.go          # Entry point, Gin router, event handler, gateway forwarding
├── ai/
│   └── watson.go    # Watson AI client, IAM auth, prompt builder, response parser
├── Dockerfile       # Multi-stage build (golang:alpine → alpine:latest)
├── go.mod / go.sum  # Dependencies (gin, godotenv, ingestor/shared)
├── .env             # Runtime configuration (not committed in production)
└── .env.example     # Environment variable template
```

## Event Forwarding

After AI analysis, enriched events are forwarded asynchronously to the API Gateway:

```
POST http://api-gateway:8080/api/internal/events
```

The forwarding has a 10-second timeout and does not block the response to the caller. Failures are logged but do not cause the main request to fail.

## Related Repositories

| Repository | Description |
|------------|-------------|
| [ingestor](https://github.com/ibm-live-project-interns/ingestor) | Backend services (API Gateway, Ingestor Core, Event Router) |
| [datasource](https://github.com/ibm-live-project-interns/datasource) | Network event simulator and data generation |
| [ui](https://github.com/ibm-live-project-interns/ui) | React frontend dashboard |
| [infra](https://github.com/ibm-live-project-interns/infra) | Infrastructure orchestration and deployment |
