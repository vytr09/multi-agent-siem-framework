"""
Local Knowledge Base Implementation
Uses ChromaDB and Local Embeddings (SentenceTransformers)
"""
import os
# Disable ChromaDB telemetry to prevent errors
os.environ["ANONYMIZED_TELEMETRY"] = "False"
import json
import logging
import hashlib
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime
import asyncio

try:
    import chromadb
    from chromadb.config import Settings
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    chromadb = None
    Chroma = None
    HuggingFaceEmbeddings = None

from core.logging import get_agent_logger

# Suppress annoying ChromaDB telemetry errors
class TelemetryFilter(logging.Filter):
    def filter(self, record):
        return "telemetry event" not in record.getMessage()

logging.getLogger().addFilter(TelemetryFilter())
logging.getLogger("chromadb").addFilter(TelemetryFilter())
logging.getLogger("posthog").addFilter(TelemetryFilter())

class KBManager:
    """
    Manages the Knowledge Base for the framework.
    Handles storage and retrieval of TTPs, Rules, and Events.
    """
    
    COLLECTION_RULES = "sigma_rules"
    COLLECTION_TTPS = "historical_ttps"
    COLLECTION_REPORTS = "investigations"
    COLLECTION_MITRE = "mitre_attack"
    
    def __init__(self, persist_dir: str = "data/chroma_db", embedding_model: str = "BAAI/bge-small-en-v1.5"):
        self.logger = get_agent_logger("kb_manager")
        
        if not chromadb:
            self.logger.error("ChromaDB or LangChain dependencies missing. KB disabled.")
            self.enabled = False
            return
            
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.enabled = True
        
        # Initialize Embeddings (CPU Optimized)
        self.logger.info(f"Loading local embedding model: {embedding_model}...")
        self.embeddings = HuggingFaceEmbeddings(
            model_name=embedding_model,
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )
        
        # Initialize Client (Persistent)
        settings = Settings(anonymized_telemetry=False)
        self.client = chromadb.PersistentClient(path=str(self.persist_dir), settings=settings)
        self.lock = asyncio.Lock()
        
        self.logger.info("Knowledge Base initialized successfully")

    # ... (skipping unchanged methods)

    async def add_mitre_technique(self, technique: Dict[str, Any]):
        """
        Add a MITRE ATT&CK technique to the KB.
        """
        if not self.enabled: return
        
        try:
            async with self.lock:
                for attempt in range(2):
                    try:
                        vector_store = self._get_vector_store(self.COLLECTION_MITRE)
                        
                        text_content = f"""
                        Technique: {technique.get('name')} ({technique.get('external_id')})
                        Description: {technique.get('description')}
                        Detection: {technique.get('detection', 'N/A')}
                        Platforms: {', '.join(technique.get('platforms', []))}
                        """
                        
                        metadata = {
                            "attack_id": technique.get("external_id"),
                            "name": technique.get("name"),
                            "url": technique.get("url", ""),
                            "full_json": json.dumps(technique)
                        }
                        
                        id_hash = technique.get("external_id") # Use Attack ID as unique ID
                        
                        await vector_store.aadd_texts(
                            texts=[text_content],
                            metadatas=[metadata],
                            ids=[id_hash]
                        )
                        break
                    except Exception as e:
                        if "Component not running" in str(e) and attempt == 0:
                            self._reset_client()
                            continue
                        # Ignore ID verification errors (duplicates)
                        if "ID" in str(e) and "already exists" in str(e):
                            break
                        raise e
        except Exception as e:
            self.logger.error(f"Failed to add MITRE technique to KB: {e}")

    async def query_mitre_context(self, query: str, n_results: int = 3) -> str:
        """
        Retrieve relevant MITRE context for a query (report text).
        Returns a formatted string of potential techniques.
        """
        if not self.enabled: return ""
        
        try:
            async with self.lock:
                # Using simple similarity search
                vector_store = self._get_vector_store(self.COLLECTION_MITRE)
                results = await vector_store.asimilarity_search(query, k=n_results)
                
                context_parts = []
                for doc in results:
                    tech_id = doc.metadata.get("attack_id")
                    name = doc.metadata.get("name")
                    content = doc.page_content
                    # Limit content length to save tokens
                    if "Description:" in content: 
                        desc = content.split("Description:")[1].split("Detection:")[0].strip()[:300] + "..."
                    else:
                        desc = content[:300]
                    
                    context_parts.append(f"- {name} ({tech_id}): {desc}")
                
                if not context_parts:
                    return ""
                    
                return "Potential MITRE Techniques found in Knowledge Base:\n" + "\n".join(context_parts)
                
        except Exception as e:
            self.logger.error(f"KB Retrieval Failed: {e}")
            return ""

    def _generate_id(self, content: str) -> str:
        """Generate SHA256 hash for ID"""
        return hashlib.sha256(content.encode()).hexdigest()

    def _reset_client(self):
        """Re-initialize the client after a crash"""
        try:
            self.logger.warning("Resetting ChromaDB client...")
            settings = Settings(anonymized_telemetry=False)
            self.client = chromadb.PersistentClient(path=str(self.persist_dir), settings=settings)
            self.logger.info("ChromaDB client reset successfully.")
        except Exception as e:
            self.logger.error(f"Failed to reset ChromaDB: {e}")

    def _get_vector_store(self, collection_name: str) -> 'Chroma':
        """Get LangChain vector store interface for a collection"""
        if not self.enabled: return None
        
        # No proactive check - rely on reactive recovery
        # self._check_client()
        
        return Chroma(
            client=self.client,
            collection_name=collection_name,
            embedding_function=self.embeddings,
        )

    async def add_sigma_rule(self, rule: Dict[str, Any], status: str = "verified"):
        """
        Add a verified Sigma rule to the KB.
        Index primarily by Description and Title.
        """
        if not self.enabled: return
        
        try:
            async with self.lock:
                # Retry logic
                for attempt in range(2):
                    try:
                        vector_store = self._get_vector_store(self.COLLECTION_RULES)
                        
                        # Create text representation for embedding
                        text_content = f"""
                        Title: {rule.get('title')}
                        Description: {rule.get('description')}
                        Technique: {rule.get('tags', [])}
                        Log Source: {rule.get('logsource', {})}
                        """
                        
                        metadata = {
                            "rule_id": str(rule.get("id", "")),
                            "title": rule.get("title", "Unknown"),
                            "status": status,
                            "timestamp": datetime.utcnow().isoformat(),
                            "full_json": json.dumps(rule)
                        }
                        
                        id_hash = self._generate_id(text_content)
                        
                        await vector_store.aadd_texts(
                            texts=[text_content],
                            metadatas=[metadata],
                            ids=[id_hash]
                        )
                        self.logger.info(f"Added Sigma rule to KB: {rule.get('title')}")
                        break # Success
                    except Exception as e:
                        if "Component not running" in str(e) and attempt == 0:
                            self.logger.warning(f"ChromaDB crashed (attempt {attempt}). Resetting and retrying...")
                            self._reset_client()
                            continue
                        raise e

        except Exception as e:
            self.logger.error(f"Failed to add Sigma rule to KB: {e}")

    async def query_similar_rules(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Find rules similar to the query (e.g., "Windows Process Creation rule for mimikatz")
        """
        if not self.enabled: return []
        
        try:
            async with self.lock:
                for attempt in range(2):
                    try:
                        vector_store = self._get_vector_store(self.COLLECTION_RULES)
                        results = await vector_store.asimilarity_search(query, k=n_results)
                        
                        rules = []
                        for doc in results:
                            try:
                                rule_json = json.loads(doc.metadata.get("full_json", "{}"))
                                rules.append(rule_json)
                            except Exception:
                                continue
                        return rules
                    except Exception as e:
                        if "Component not running" in str(e) and attempt == 0:
                            self.logger.warning(f"ChromaDB crashed (attempt {attempt}). Resetting...")
                            self._reset_client()
                            continue
                        # If simple unrelated error, return empty logic handled by outer except? 
                        # Actually previous code caught exception and returned [].
                        raise e
                        
        except Exception as e:
            self.logger.error(f"KB Query Failed: {e}")
            return []

    async def add_ttp(self, ttp: Dict[str, Any], report_id: str):
        """
        Add an extracted TTP to history.
        Index by Description and Indicators.
        """
        if not self.enabled: return
        
        try:
            async with self.lock:
                for attempt in range(2):
                    try:
                        vector_store = self._get_vector_store(self.COLLECTION_TTPS)
                        
                        text_content = f"""
                        Technique: {ttp.get('technique_name')} ({ttp.get('attack_id')})
                        Description: {ttp.get('description')}
                        Indicators: {', '.join(ttp.get('indicators', []))}
                        """
                        
                        metadata = {
                            "attack_id": ttp.get("attack_id"),
                            "report_id": report_id,
                            "timestamp": datetime.utcnow().isoformat(),
                            "full_json": json.dumps(ttp)
                        }
                        
                        id_hash = self._generate_id(text_content + report_id)
                        
                        await vector_store.aadd_texts(
                            texts=[text_content],
                            metadatas=[metadata],
                            ids=[id_hash]
                        )
                        break
                    except Exception as e:
                        if "Component not running" in str(e) and attempt == 0:
                            self.logger.warning("ChromaDB crashed. Resetting...")
                            self._reset_client()
                            continue
                        raise e
        except Exception as e:
            self.logger.error(f"Failed to add TTP to KB: {e}")

    async def check_duplicate_report(self, content: str) -> bool:
        """
        Check if this report content has been processed before.
        Uses exact hash match first, could use vector search for "near duplicate" later.
        """
        if not self.enabled: return False
        
        # 1. content hash check (Metadata lookup not supported efficiently in pure Chroma/LC usually, 
        # so we might rely on ID existence if we use hash as ID)
        content_hash = self._generate_id(content)
        
        # Check if ID exists (try to get it)
        try:
            async with self.lock:
                for attempt in range(2):
                    try:
                        # self._check_client() # No longer exists
                        col = self.client.get_collection(self.COLLECTION_REPORTS)
                        existing = col.get(ids=[content_hash])
                        if existing and existing['ids']:
                            return True
                        # If successful check, break/return
                        return False
                    except Exception as e:
                        if "Component not running" in str(e) and attempt == 0:
                            self._reset_client()
                            continue
                        raise e
        except Exception:
            return False
            
        return False
        
    async def register_report(self, content: str, report_metadata: Dict[str, Any]):
        """Register a processed report to prevent re-processing"""
        if not self.enabled: return
        
        try:
            async with self.lock:
                for attempt in range(2):
                    try:
                        vector_store = self._get_vector_store(self.COLLECTION_REPORTS)
                        
                        content_hash = self._generate_id(content)
                        
                        # We index the Summary or Title for vector search, but use Hash for ID
                        text_content = f"Processed Report: {report_metadata.get('title', 'Unknown')}\nSummary: {content[:500]}"
                        
                        await vector_store.aadd_texts(
                            texts=[text_content],
                            metadatas=[report_metadata],
                            ids=[content_hash]
                        )
                        break
                    except Exception as e:
                        if "Component not running" in str(e) and attempt == 0:
                            self._reset_client()
                            continue
                        raise e
        except Exception as e:
            self.logger.error(f"KB Register Failed: {e}")

    def _generate_id(self, content: str) -> str:
        """Generate SHA256 hash for ID"""
        return hashlib.sha256(content.encode()).hexdigest()

# Singleton
_kb_manager = None

def get_kb_manager() -> Optional[KBManager]:
    global _kb_manager
    if not _kb_manager:
        # Default configuration
        try:
            _kb_manager = KBManager()
        except Exception as e:
            print(f"KB Init Failed: {e}")
            return None
    return _kb_manager
