# Troubleshooting

Common issues and solutions for THREATWISE framework.

## Installation Issues

### ImportError: No module named 'langchain'

**Cause**: Dependencies not installed or virtual environment not activated

**Solution**:
```bash
# Activate venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Reinstall dependencies
pip install -r requirements.txt
```

### ChromaDB PersistentClient error

**Cause**: Database corruption or permission issues

**Solution**:
```bash
# Remove and recreate database
rm -rf data/chromadb
python scripts/populate_mitre_kb.py
```

---

## API Connection Errors

### LLM API timeout

**Cause**: Network issues or rate limiting

**Solution**:
```yaml
# Increase timeout in config/agents.yaml
llm:
  timeout: 60  # seconds
  max_retries: 5
```

### API key invalid

**Symptoms**: `401 Unauthorized` or `403 Forbidden`

**Solution**:
```bash
# Verify API keys in .env
echo $GEMINI_API_KEY
echo $CEREBRAS_API_KEY

# Test directly
curl -H "Authorization: Bearer $GEMINI_API_KEY" \
  https://generativelanguage.googleapis.com/v1/models
```

---

## SIEM Integration Problems

### Splunk connection refused

**Check list**:
1. Splunk service running: `splunk status`
2. API port accessible: `telnet <SPLUNK_HOST> 8089`
3. Credentials correct in `.env`
4. SSL verification disabled for dev: `SPLUNK_VERIFY_SSL=false`

**Test connection**:
```bash
curl -k -u admin:password \
  https://<SPLUNK_HOST>:8089/services/auth/login
```

### Rules not detecting attacks

**Debug steps**:
1. Verify attack executed: Check SSH logs
2. Check Splunk indexing: `index=main | head 10`
3. Test query manually in Splunk UI
4. Check field mappings (Sysmon vs Windows Event Log)

**Common issue**: Splunk checkpoint not reset
```bash
# On Splunk forwarder
rm -rf $SPLUNK_HOME/var/lib/splunk/modinputs/*
./splunk restart
```

---

## SSH Authentication Failures

### Permission denied (publickey)

**Solution**:
```bash
# Generate key
ssh-keygen -t ed25519 -f ~/.ssh/threatwise_key

# Copy to target
ssh-copy-id -i ~/.ssh/threatwise_key.pub user@<SSH_HOST>

# Update .env
SSH_KEY_PATH=/home/user/.ssh/threatwise_key
SSH_PASSWORD=  # Leave empty when using key
```

### Connection timeout

**Check**:
1. SSH service running: `Get-Service sshd` (Windows)
2. Firewall allows port 22
3. Correct IP/hostname in `.env`

---

## LLM Provider Issues

### Gemini API quota exceeded

**Temporary workaround**:
```yaml
# Switch to Cerebras in config/agents.yaml
llm:
  provider: openai
  model: llama-3.3-70b
  api_key: ${CEREBRAS_API_KEY}
  base_url: https://api.cerebras.ai/v1
```

### Hallucination in extractions

**Solutions**:
1. Lower temperature: `temperature: 0.2`
2. Enable NLP preprocessing: `nlp.enabled: true`
3. Increase confidence threshold: `min_threshold: 0.7`
4. Add few-shot examples to prompt

---

## Performance Optimization

### Slow pipeline execution

**Optimizations**:
```yaml
# Increase parallelism
processing:
  max_concurrent: 5
  batch_size: 10

# Enable caching
enable_caching: true
cache_ttl: 7200
```

### High memory usage

**Solutions**:
1. Reduce batch size
2. Clear ChromaDB periodically
3. Limit max_tokens in LLM config
4. Process reports sequentially instead of parallel

---

## Debugging Tips

### Enable verbose logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Or in `config/logging.yaml`:
```yaml
loggers:
  root:
    level: DEBUG
```

### Inspect LLM prompts

```yaml
# In agents.yaml
llm:
  debug: true  # Log full prompts and responses
```

### Test individual agents

```python
from agents.extractor.agent import ExtractorAgent

agent = ExtractorAgent("test", config)
result = await agent.execute({"reports": [...]})
print(result)
```

---

## Common Error Messages

**"TTP confidence below threshold"**
- Increase `min_threshold` or improve report quality

**"Sigma validation failed"**
- Check rule syntax manually
- Enable optimization: `sigma.optimization: true`

**"Attack command blocked by safety filter"**
- Review safety level: `safety_level: medium`
- Manually approve command if safe

**"ChromaDB collection not found"**
- Run: `python scripts/populate_mitre_kb.py`

---

## Getting Help

1. Check logs: `logs/system.log`
2. Review agent-specific configs
3. Test components in isolation
4. File issue with error trace

For architecture questions, see [architecture.md](architecture.md).  
For agent-specific issues, see [agents.md](agents.md).
