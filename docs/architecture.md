# System Architecture

This document provides a detailed technical overview of the THREATWISE system architecture.

## Design Principles

THREATWISE is built on three core principles:

1. **Specialization**: Each agent focuses on a single responsibility (extraction, generation, evaluation)
2. **Context Management**: Distributed processing avoids token limit issues with long CTI reports
3. **Fault Isolation**: Agent failures are contained and recoverable

---

## Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Interface & Data Collection                       │
│  - Next.js Dashboard (Real-time monitoring)                 │
│  - FastAPI Gateway (API endpoints)                          │
│  - Collector Module (MISP, OpenCTI, manual upload)          │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Orchestration (LangChain)                         │
│  - SecurityWorkflow (LangGraph state machine)               │
│  - Task scheduling and parallelization                      │
│  - Feedback loop coordination                               │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Agent Layer                                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │ Extractor  │→ │  RuleGen   │→ │ AttackGen  │→ [Eval]  │
│  │   Agent    │  │   Agent    │  │   Agent    │           │
│  └────────────┘  └────────────┘  └────────────┘           │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Infrastructure                                     │
│  - LLM Providers (Gemini, Llama via Cerebras)              │
│  - Vector DB (ChromaDB for RAG)                            │
│  - SIEM (Splunk Enterprise)                                │
│  - Sandbox (Windows execution environment)                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Pipeline Execution Workflow

```
CTI Report Input
      │
      ▼
┌─────────────────┐
│ 1. Collection   │  Normalize format, extract metadata
└─────────────────┘
      │
      ▼
┌─────────────────┐
│ 2. Extraction   │  NLP + LLM → Structured TTPs
└─────────────────┘
      │
      ▼
┌─────────────────┐
│ 3. Optimization │  Deduplication, confidence filtering
└─────────────────┘
      │
      ├──────────────┬──────────────┐
      ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│ RuleGen  │  │ RuleGen  │  │ RuleGen  │  (Parallel for each TTP)
└──────────┘  └──────────┘  └──────────┘
      │              │              │
      ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│AttackGen │  │AttackGen │  │AttackGen │  (Parallel)
└──────────┘  └──────────┘  └──────────┘
      │              │              │
      └──────────────┴──────────────┘
                  │
                  ▼
          ┌──────────────┐
          │ SIEM Verify  │  Execute + Detect
          └──────────────┘
                  │
                  ▼
          ┌──────────────┐
          │  Evaluator   │  Score + Feedback
          └──────────────┘
                  │
            ┌─────┴─────┐
            │           │
         Pass        Fail
            │           │
            ▼           ▼
        Output    [Regenerate] → Loop back to RuleGen
```

---

## Technology Stack

### Core Framework
- **LangChain**: Agent orchestration and LLM abstraction
- **LangGraph**: State machine workflow management
- **Pydantic**: Structured output validation

### LLM Providers
- **Google Gemini**: Primary extraction and generation
- **Cerebras**: High-speed Llama 3.3 70B inference
- **OpenAI**: Fallback provider

### Data Storage
- **ChromaDB**: Vector database for RAG
- **JSON**: Structured data exchange
- **Splunk**: Log storage and query engine

### Web Stack
- **Backend**: FastAPI + Uvicorn
- **Frontend**: Next.js 14, React, TailwindCSS
- **API**: RESTful with WebSocket for real-time updates

---

## Security Considerations

### Attack Execution Sandbox

- Isolated Windows VM with network monitoring
- SSH-based remote execution (no RDP)
- Automatic log cleanup between runs
- Safety filters on generated commands

### API Key Management

- Environment variables (never hardcoded)
- Separate dev/prod credentials
- Rate limiting on LLM API calls

---

## Performance Benchmarks

| Operation | Time (avg) | Notes |
|-----------|-----------|-------|
| TTP Extraction | 15s | For 5-page report |
| Rule Generation | 8s | Per TTP with RAG |
| Attack Execution | 5s | SSH command run |
| SIEM Query | 3s | Query + wait for indexing |
| Full Pipeline | 2-5 min | Depends on TTP count |

*Benchmarked on: Intel i7-9700K, 16GB RAM, 1Gbps network*
