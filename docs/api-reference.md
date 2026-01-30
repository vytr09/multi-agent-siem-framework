# API Reference

FastAPI backend exposes RESTful endpoints for pipeline execution and monitoring.

**Base URL**: `http://localhost:8000`  
**API Docs**: `http://localhost:8000/docs` (Swagger UI)

---

## Pipeline Endpoints

### Execute Pipeline

```http
POST /api/pipeline/run
Content-Type: application/json
```

**Request Body:**
```json
{
  "reports": [
    {
      "id": "report_001",
      "content": "CTI report text...",
      "source": "MISP"
    }
  ],
  "context": {
    "threat_actor": "APT28"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "extraction": {
    "reports_processed": 1,
    "total_ttps_extracted": 5
  },
  "rules": {
    "rules": [...]
  },
  "final_score": 0.85,
  "siem_metrics": {
    "detection_rate": 0.92
  }
}
```

###Get Latest Result

```http
GET /api/pipeline/latest
```

### Get Execution History

```http
GET /api/pipeline/history?limit=10
```

---

## Agent Management

### Run Single Agent

```http
POST /api/agents/run
Content-Type: application/json
```

**Request:**
```json
{
  "agent_name": "extractor",
  "input_data": {
    "reports": [...]
  }
}
```

### Get Agent Status

```http
GET /api/agents/status
```

**Response:**
```json
{
  "agents": {
    "extractor": "ready",
    "rulegen": "ready",
    "evaluator": "ready",
    "attackgen": "ready"
  }
}
```

### Start/Stop Agent

```http
POST /api/agents/{agent_name}/start
POST /api/agents/{agent_name}/stop
```

---

## Logs

### Retrieve Logs

```http
GET /api/logs?level=INFO&limit=100
```

**Query Parameters:**
- `level`: DEBUG | INFO | WARNING | ERROR
- `limit`: Number of entries (default: 100)

---

## WebSocket (Real-time Updates)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Pipeline progress:', data.status);
};
```

---

## Error Responses

All endpoints return standard error format:

```json
{
  "status": "error",
  "message": "Error description",
  "code": "ERROR_CODE"
}
```

**Common Error Codes:**
- `INVALID_INPUT`: Malformed request
- `LLM_API_ERROR`: LLM provider failure
- `SIEM_CONNECTION_ERROR`: SIEM unreachable
- `INTERNAL_ERROR`: Server error

---

## Authentication

Currently no authentication required (development mode).

For production, add Bearer token:
```http
Authorization: Bearer <your_token>
```
