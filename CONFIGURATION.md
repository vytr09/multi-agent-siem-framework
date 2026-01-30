# Configuration Reference

This document provides detailed configuration options for the THREATWISE framework.

## Environment Variables

### Core Application Settings

```bash
# Application metadata
APP_NAME='Multi-Agent SIEM Framework'
APP_VERSION='1.0.0'
DEBUG='false'                    # Set to 'true' for verbose logging
ENVIRONMENT='production'         # development | staging | production
```

### LLM Provider Configuration

#### Google Gemini

```bash
GEMINI_API_KEY='your_api_key_here'
GEMINI_MODEL='gemini-1.5-pro'    # Optional: Override default model
```

**Used for**: Extractor Agent, RuleGen Agent (default)  
**Get API key**: https://makersuite.google.com/app/apikey

#### Cerebras (Llama Models)

```bash
CEREBRAS_API_KEY='your_api_key_here'
CEREBRAS_MODEL='llama-3.3-70b'   # Default model
```

**Used for**: High-speed inference tasks  
**Get API key**: https://cloud.cerebras.ai/

#### OpenAI (Optional)

```bash
OPENAI_API_KEY='your_api_key_here'
OPENAI_MODEL='gpt-4-turbo'       # Optional
```

**Used for**: Fallback LLM provider

### SIEM Integration

#### Splunk Enterprise

```bash
SPLUNK_HOST='splunk.example.com'
SPLUNK_PORT='8089'               # API port, not web UI port
SPLUNK_USER='admin'
SPLUNK_PASSWORD='your_password'
SPLUNK_VERIFY_SSL='false'        # Set to 'true' in production
```

**Required for**: Rule verification, attack detection

#### SSH Access (Test Environment)

```bash
SSH_HOST='192.168.1.100'
SSH_PORT='22'
SSH_USER='administrator'
SSH_PASSWORD='your_password'     # Use SSH_KEY_PATH instead for production
SSH_KEY_PATH=''                  # Path to private key file (recommended)
```

**Required for**: Attack command execution

### CTI Sources

#### MISP

```bash
MISP_URL='https://misp.example.com'
MISP_API_KEY='your_misp_api_key'
MISP_VERIFY_CERT='false'
```

**Optional**: For automated CTI report collection

---

## Agent Configuration

Configuration files are located in `config/` directory.

### config/agents.yaml

This file controls agent behavior and LLM parameters.

#### Extractor Agent

```yaml
agents:
  extractor:
    name: CTI Collector Agent
    memory_enabled: true
    llm:
      provider: openai              # openai | google | cerebras
      model: llama-3.3-70b
      api_key: ${CEREBRAS_API_KEY}
      base_url: https://api.cerebras.ai/v1
      max_tokens: 4000
      temperature: 0.3               # Lower = more deterministic
    nlp:
      enabled: true
      language: en
      enable_ioc_detection: true
    confidence_scoring:
      min_threshold: 0.5             # Minimum confidence to keep TTP
      high_confidence_threshold: 0.8
```

**Key parameters:**
- `temperature`: Controls LLM creativity (0.0-1.0). Lower for extraction tasks.
- `max_tokens`: Maximum output length. Increase for detailed reports.
- `min_threshold`: Filters low-confidence TTPs

#### RuleGen Agent

```yaml
  rulegen:
    name: Rule Generation Agent
    memory_enabled: true
    use_feedback: true
    min_confidence_threshold: 0.5
    feedback:
      enabled: true
      lookback: 3                    # Number of previous iterations to consider
    llm:
      provider: openai
      model: llama-3.3-70b
      temperature: 0.3
      max_tokens: 8000               # Larger for rule generation
    sigma:
      output_formats:
        - sigma
        - splunk
      optimization: true
```

**Key parameters:**
- `use_feedback`: Enable self-correction loop
- `lookback`: Number of feedback iterations
- `output_formats`: Target SIEM platforms

#### AttackGen Agent

```yaml
  attackgen:
    name: Attack Generation Agent
    platforms:
      - windows
      - linux
    safety_level: medium             # low | medium | high
    llm:
      temperature: 0.5               # Higher for creative attack generation
      max_tokens: 8000
```

**Safety levels:**
- `high`: Only non-destructive commands
- `medium`: Allows process/registry modifications
- `low`: Full attack simulation (destructive)

#### Evaluator Agent

```yaml
  evaluator:
    name: Performance Evaluator Agent
    memory_enabled: true
    feedback_enabled: true
    auto_iterate: false              # Manual control of feedback loop
    max_iterations: 3
    benchmark:
      use_llm_judge: true
      thresholds:
        minimum_score: 0.7
        high_quality_score: 0.85
```

**Key parameters:**
- `auto_iterate`: Automatically retry on low scores
- `max_iterations`: Maximum feedback loop cycles
- `minimum_score`: Threshold for accepting rules

### Feedback Loop Configuration

```yaml
feedback:
  enabled: true
  max_iterations: 3
  minimum_score: 0.7
  improvement_threshold: 0.05        # Minimum improvement to continue iterating
```

---

## Provider Configuration

### config/providers.yaml

Defines available LLM providers and models.

```yaml
providers:
  openai:
    models:
      - name: gpt-4-turbo
        max_tokens: 128000
        supports_json: true
      - name: gpt-3.5-turbo
        max_tokens: 16000
  
  google:
    models:
      - name: gemini-1.5-pro
        max_tokens: 1000000
        supports_json: true
  
  cerebras:
    models:
      - name: llama-3.3-70b
        max_tokens: 8192
        api_base: https://api.cerebras.ai/v1
```

---

## Logging Configuration

### config/logging.yaml

```yaml
version: 1
formatters:
  standard:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: standard
  file:
    class: logging.handlers.RotatingFileHandler
    filename: logs/system.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    level: DEBUG
loggers:
  root:
    level: INFO
    handlers: [console, file]
  langchain_orchestrator:
    level: DEBUG
```

**Adjust logging levels:**
- `DEBUG`: Verbose output for development
- `INFO`: Standard operational logging
- `WARNING`: Only warnings and errors
- `ERROR`: Only error messages

---

## Benchmark Configuration

### config/benchmark_config.yaml

```yaml
benchmarks:
  intelex_comparison:
    dataset_path: data/datasets/intelex_gt
    ground_truth_file: intelex_ground_truth.json
    metrics:
      - precision
      - recall
      - f1_score
  
  rule_quality:
    llm_judge_model: llama-3.3-70b
    criteria:
      - accuracy
      - completeness
      - efficiency
      - maintainability
```

---

## Advanced Configuration

### Vector Database (ChromaDB)

ChromaDB settings are configured in code. To modify:

```python
# core/knowledge_base.py
self.client = chromadb.PersistentClient(
    path="data/chromadb",
    settings=Settings(
        anonymized_telemetry=False,
        allow_reset=True
    )
)
```

### Parallel Execution

```yaml
# In agents.yaml
processing:
  batch_size: 5              # Number of TTPs to process in parallel
  max_concurrent: 3          # Maximum concurrent LLM calls
  enable_caching: true
```

---

## Configuration Best Practices

1. **Use environment variables for secrets**: Never commit `.env` to version control
2. **Adjust temperature based on task**:
   - Extraction: 0.2-0.3 (deterministic)
   - Generation: 0.3-0.5 (balanced)
   - Creative tasks: 0.6-0.8 (exploratory)
3. **Monitor token usage**: Set `max_tokens` based on report length
4. **Enable feedback cautiously**: Each iteration costs additional API calls
5. **Use SSH keys over passwords**: More secure for production

---

## Troubleshooting Configuration Issues

**Issue**: LLM API timeouts
```yaml
# Increase timeout in agent config
llm:
  timeout: 60  # seconds
```

**Issue**: Out of memory errors
```yaml
# Reduce concurrent processing
processing:
  max_concurrent: 1
  batch_size: 1
```

**Issue**: High API costs
```yaml
# Use cheaper models for non-critical agents
llm:
  model: gpt-3.5-turbo  # Instead of gpt-4
```

For more help, see [docs/troubleshooting.md](docs/troubleshooting.md).
