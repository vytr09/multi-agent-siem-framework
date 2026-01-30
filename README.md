# THREATWISE

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-2D3748.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-2D3748.svg)](LICENSE)
[![LangChain](https://img.shields.io/badge/framework-LangChain-2D3748.svg)](https://github.com/langchain-ai/langchain)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14.1-2D3748.svg)](https://attack.mitre.org/)

**THREAT** intelligence extraction and **WISE** adaptive rule synthesis for SIEM defense

A multi-agent framework for automated SIEM rule generation from Cyber Threat Intelligence reports using LLMs with SIEM-in-the-loop verification and self-correction feedback.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Performance Metrics](#performance-metrics)
- [Publications](#publications)
- [License](#license)

---

## Overview

Current Security Operations Centers (SOC) face significant challenges in translating Cyber Threat Intelligence (CTI) reports into actionable SIEM detection rules. This process is traditionally manual, time-consuming (days to weeks), and prone to errors, resulting in high false positive rates and delayed threat response.

THREATWISE addresses these limitations through an autonomous multi-agent system that:
1. Extracts Tactics, Techniques, and Procedures (TTPs) from unstructured CTI reports
2. Generates platform-specific detection rules (Sigma/SPL format)
3. Synthesizes custom attack commands for verification
4. Validates rules against live SIEM infrastructure
5. Iteratively refines rules through automated feedback loops

The system reduces the CTI-to-rule deployment cycle from weeks to minutes while automating 80-90% of manual analyst workload.

---

## Architecture

THREATWISE implements a layered architecture consisting of four specialized AI agents orchestrated via LangGraph state machines:

```
┌─────────────────────────────────────────────────────────────┐
│                    Interface Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Next.js    │  │   FastAPI    │  │   Collector  │     │
│  │  Dashboard   │  │   Gateway    │  │    Module    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│              Orchestration Layer (LangChain)                │
│         Graph-based State Machine + Workflow Control        │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│                    Agent Layer                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │Extractor │→ │ RuleGen  │→ │ AttackGen │→ │Evaluator │ │
│  │  Agent   │  │  Agent   │  │   Agent   │  │  Agent   │ │
│  └──────────┘  └──────────┘  └───────────┘  └──────────┘ │
│     │              │               │              │        │
│     └──────────────┴───────────────┴──────────────┘        │
│                 Feedback Loop (Reflexion)                   │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│              Infrastructure Layer                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │    LLM     │  │   Vector   │  │   Splunk   │           │
│  │ Providers  │  │ DB (Chroma)│  │ Enterprise │           │
│  └────────────┘  └────────────┘  └────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### Agent Responsibilities

| Agent | Function | Technology |
|-------|----------|------------|
| **Extractor** | Hybrid NLP + LLM extraction of TTPs from CTI reports | spaCy, Gemini/Llama |
| **RuleGen** | Sigma rule generation with RAG-enhanced prompting | LangChain, ChromaDB |
| **AttackGen** | Synthesis of platform-specific attack commands | RAG, Few-shot Learning |
| **Evaluator** | LLM-as-a-Judge quality scoring + SIEM verification | Structured Output Parsing |

---

## Key Features

- **Hybrid Extraction**: Combines rule-based NLP preprocessing with LLM semantic understanding for robust TTP extraction
- **MITRE ATT&CK Integration**: Automatic mapping to ATT&CK framework with fuzzy matching and validation
- **Multi-Platform Rules**: Generates Sigma rules with automated SPL conversion for Splunk
- **Customized Attack Generation**: Synthesizes attack commands tailored to extracted TTPs (not limited to Atomic Red Team)
- **SIEM-in-the-Loop Verification**: Executes attacks on sandbox and validates detection in real Splunk environment
- **Self-Correction Feedback**: Iterative refinement using Reflexion pattern with up to 3 improvement cycles
- **RAG-Enhanced Generation**: Leverages verified rule history via vector similarity search
- **Confidence Scoring**: Multi-factor confidence assessment (7 weighted factors) for extracted TTPs

---

## Installation

See [INSTALLATION.md](INSTALLATION.md) for comprehensive setup instructions.

### Prerequisites

- Python 3.10 or higher
- Node.js 18+ (for web dashboard)
- Splunk Enterprise (optional, for SIEM verification)
- SSH access to Windows test environment (optional, for attack execution)

### Quick Setup

```bash
# Clone repository
git clone https://github.com/vytr09/multi-agent-siem-framework.git
cd multi-agent-siem-framework

# Backend setup
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your LLM API keys and SIEM credentials

# Frontend setup (optional)
cd web
npm install
npm run dev
```

---

## Quick Start

### Running the Pipeline via CLI

```python
import asyncio
from core.langchain_orchestrator import LangChainOrchestrator

async def main():
    # Initialize orchestrator
    orchestrator = LangChainOrchestrator(mode="langchain")
    await orchestrator.initialize()
    
    # Process CTI report
    cti_reports = [{
        "id": "APT28_report_2024",
        "content": "Threat actor APT28 uses PowerShell for credential dumping...",
        "source": "MISP"
    }]
    
    # Run full pipeline with feedback loop
    result = await orchestrator.run_pipeline(cti_reports)
    
    print(f"Extracted {len(result['extraction']['extraction_results'])} TTPs")
    print(f"Generated {len(result['rules']['rules'])} Sigma rules")
    print(f"Detection rate: {result['siem_metrics']['detection_rate']:.2%}")
    print(f"Average quality score: {result['final_score']:.2f}/1.0")

asyncio.run(main())
```

### Using the Web Dashboard

```bash
# Start backend
cd api
uvicorn main:app --reload

# Start frontend (separate terminal)
cd web
npm run dev

# Navigate to http://localhost:3000
```

### Running Benchmarks

```bash
# TTP extraction benchmark (IntelEx comparison)
python scripts/run_intelex_benchmark.py

# Rule generation quality benchmark
python scripts/benchmark_runner.py --config config/benchmark_config.yaml
```

---

## Documentation

- [Configuration Guide](CONFIGURATION.md) - Agent parameters, LLM settings, SIEM credentials
- [Agent Reference](docs/agents.md) - Detailed agent methodologies and algorithms
- [API Documentation](docs/api-reference.md) - FastAPI endpoint specifications
- [Benchmarking Guide](docs/benchmarking.md) - Reproducing experimental results
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [Development Guide](docs/development.md) - Contributing and extending the system

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
