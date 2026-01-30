# Agent Reference

This document provides detailed information about each specialized agent in the THREATWISE framework.

## 1. Extractor Agent

**Purpose**: Extract TTPs from unstructured CTI reports using hybrid NLP + LLM approach.

### Methodology

**Phase 1: NLP Preprocessing**
- Text cleaning and normalization
- Entity extraction (malware, tools, APT groups)
- IOC detection (IPs, domains, hashes, registry keys)
- Keyword-based TTP indicators

**Phase 2: LLM Extraction**
- Enriched prompt with NLP results
- Structured output via Pydantic models
- MITRE ATT&CK mapping
- Confidence scoring (7 weighted factors)

### Configuration

```yaml
agents:
  extractor:
    llm:
      model: llama-3.3-70b
      temperature: 0.3          # Lower for deterministic extraction
      max_tokens: 4000
    nlp:
      enabled: true
      enable_ioc_detection: true
    confidence_scoring:
      min_threshold: 0.5
```

### Output Format

```json
{
  "ttp_id": "ttp_001",
  "technique_id": "T1003.001",
  "technique_name": "LSASS Memory",
  "tactic": "Credential Access",
  "description": "Adversary dumped LSASS using procdump",
  "confidence": 0.92,
  "iocs": {
    "tools": ["procdump.exe"],
    "commands": ["procdump -ma lsass.exe lsass.dmp"]
  }
}
```

---

## 2. RuleGen Agent

**Purpose**: Generate Sigma detection rules from extracted TTPs using RAG-enhanced prompting.

### Methodology

**Step 1: RAG Retrieval**
- Query ChromaDB for similar verified rules
- Embedding-based similarity search (top-5)

**Step 2: LLM Generation**
- Structured prompt with TTP context + similar rules
- Sigma rule format enforcement
- IOC integration

**Step 3: Post-Processing**
- Syntax validation
- Field optimization (wildcard → modifiers)
- SPL conversion

### Configuration

```yaml
agents:
  rulegen:
    llm:
      temperature: 0.3
      max_tokens: 8000
    sigma:
      optimization: true
      output_formats: [sigma, splunk]
    use_feedback: true
    feedback:
      lookback: 3
```

### Example Output

```yaml
title: LSASS Memory Dump via Procdump
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects LSASS memory dumping using procdump tool
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\procdump.exe'
    CommandLine|contains: 'lsass'
  condition: selection
falsepositives:
  - Legitimate debugging
level: high
```

---

## 3. AttackGen Agent

**Purpose**: Synthesize platform-specific attack commands for SIEM verification.

### Methodology

**RAG-Enhanced Generation**
- Query KB for similar attack techniques
- Few-shot learning from verified attacks
- Platform-specific command generation (Windows/Linux)

**Safety Filtering**
- Blacklist destructive commands (format, delete)
- Sandbox-only execution
- User/admin approval for high-risk commands

### Configuration

```yaml
agents:
  attackgen:
    platforms: [windows, linux]
    safety_level: medium
    llm:
      temperature: 0.5      # Higher for creative variations
      max_tokens: 8000
```

### Example Output

```json
{
  "attack_id": "attack_001",
  "ttp_id": "T1003.001",
  "platform": "windows",
  "commands": [
    {
      "cmd": "procdump -ma lsass.exe C:\\Temp\\lsass.dmp",
      "description": "Dump LSASS memory to file",
      "requires_admin": true,
      "safety_score": 0.6
    }
  ]
}
```

---

## 4. Evaluator Agent

**Purpose**: Assess rule quality using LLM-as-a-Judge and SIEM verification results.

### Methodology

**Dual Evaluation**
1. **Qualitative**: LLM scores on 4 criteria (accuracy, completeness, efficiency, maintainability)
2. **Quantitative**: SIEM detection success (binary)

**Feedback Generation**
- Identify weaknesses (e.g., "too generic", "missing IOCs")
- Provide actionable improvements
- Track iteration history

### Configuration

```yaml
agents:
  evaluator:
    benchmark:
      use_llm_judge: true
      thresholds:
        minimum_score: 0.7
        high_quality_score: 0.85
    max_iterations: 3
    feedback_enabled: true
```

### Evaluation Output

```json
{
  "quality_score": 0.83,
  "criteria_scores": {
    "accuracy": 0.9,
    "completeness": 0.8,
    "efficiency": 0.75,
    "maintainability": 0.85
  },
  "siem_detected": true,
  "feedback": "Rule could be improved by adding parent process check",
  "iteration": 1
}
```

---

## Inter-Agent Communication

### State Graph Flow

```
Initial State
  ↓
[Extractor] → TTPs extracted
  ↓
[Optimizer] → TTPs filtered
  ↓
[Parallel Execution]
  ├─ [RuleGen TTP1] → Rule1
  ├─ [RuleGen TTP2] → Rule2
  └─ [RuleGen TTP3] → Rule3
         ↓
[Parallel Verification]
  ├─ [AttackGen + SIEM] → Result1
  ├─ [AttackGen + SIEM] → Result2
  └─ [AttackGen + SIEM] → Result3
         ↓
[Evaluator] → Scores + Feedback
         ↓
    Pass? ──Yes→ [Output]
      │
      No
      ↓
[Regenerate with Feedback] → Loop back
```

### Shared Context

Agents communicate via LangGraph state dictionary:

```python
{
  "cti_reports": [...],
  "extracted_ttps": [...],
  "optimized_ttps": [...],
  "processed_results": [
    {
      "ttp_id": "...",
      "rules": [...],
      "attacks": [...],
      "evaluation": {...},
      "iterations_used": 2
    }
  ],
  "final_report": {...}
}
```

---

## Agent-Specific Best Practices

### Extractor
- Use lower temperature (0.2-0.3) for consistency
- Enable NLP preprocessing for complex reports
- Set min confidence threshold based on report quality

### RuleGen
- Leverage RAG for better rule templates
- Enable optimization for production deployment
- Use feedback loop for iterative improvement

### AttackGen
- Balance safety vs realism (medium = recommended)
- Test commands in sandbox before production
- Keep attack command history for reproducibility

### Evaluator
- Combine LLM judge with SIEM verification
- Track improvement across iterations
- Use high threshold (0.85+) for critical rules

---

## Troubleshooting

**Extractor returns low-confidence TTPs**
- Check NLP preprocessing results
- Increase LLM temperature slightly (0.3 → 0.4)
- Verify MITRE ATT&CK mapping database is current

**RuleGen produces invalid Sigma**
- Enable optimization flag
- Check similar rules in ChromaDB
- Review feedback from previous iterations

**AttackGen fails safety check**
- Lower safety level temporarily (for testing)
- Manually review generated commands
- Add exceptions to safety filter

**Evaluator gives low scores**
- Review evaluation criteria weights
- Check SIEM detection logs
- Ensure attack commands executed successfully

For more details, see [troubleshooting.md](troubleshooting.md).
