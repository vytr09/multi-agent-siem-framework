# Local Knowledge Base (RAG) Documentation

The Multi-Agent SIEM Framework now includes a **Local Knowledge Base** (KB) powered by **ChromaDB** and **HuggingFace Embeddings**. This enables Retrieval Augmented Generation (RAG) to improve agent performance over time.

## Architecture

*   **Database**: ChromaDB (Stores persistent vector data in `data/chroma_db/`)
*   **Embeddings**: `BAAI/bge-small-en-v1.5` (Running locally on CPU, optimized for retrieval)
*   **Collections**:
    *   `sigma_rules`: Stores verified Sigma rules. Agents query this to find "gold standard" examples.
    *   `historical_ttps`: Stores extracted TTPs. Used for context awareness.
    *   `investigations`: Stores summaries of processed reports. Used for deduplication.

## Usage

### 1. Initialization
The KB Manager is initialized automatically via `core.knowledge_base.get_kb_manager()`. It requires no external API keys.

```python
from core.knowledge_base import get_kb_manager

kb = get_kb_manager()
```

### 2. Adding Learning (Rules)
When a rule passes SIEM verification, it should be added to the KB:

```python
await kb.add_sigma_rule(
    rule=sigma_rule_dict,
    status="verified"
)
```

### 3. Retrieval (RAG)
Agents can query the KB for examples before generating new content:

```python
# "Find verified rules about PowerShell downloading malware"
examples = await kb.query_similar_rules("powershell download malware", n=3)
```

### 4. Deduplication
Before processing a report, check if it's already in the KB:

```python
is_duplicate = await kb.check_duplicate_report(report_text)
if is_duplicate:
    logger.info("Skipping duplicate report")
```

## Maintenance

*   **Backup**: The database is stored in `data/chroma_db/`. Simply compress this folder to backup.
*   **Reset**: To wipe memory, delete the `data/chroma_db/` folder.
*   **Model**: The embedding model is cached in `~/.cache/huggingface/`.
