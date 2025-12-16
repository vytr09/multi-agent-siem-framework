import asyncio
import sys
import os
from pathlib import Path

# Add project root to sys.path
# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.knowledge_base import get_kb_manager

async def test_kb():
    print("Initializing KB Manager...")
    kb = get_kb_manager()
    
    if not kb or not kb.enabled:
        print("KB disabled or failed to init.")
        return

    # 1. Test Rule Addition
    print("\n[Test 1] Adding a sample Sigma rule...")
    sample_rule = {
        "id": "rule_123",
        "title": "Suspicious PowerShell Download",
        "description": "Detects PowerShell using Invoke-WebRequest to download files from external IPs.",
        "logsource": {"product": "windows", "service": "powershell"},
        "tags": ["T1059.001"]
    }
    await kb.add_sigma_rule(sample_rule)
    print("Rule added.")

    # 2. Test Retrieval (RAG)
    print("\n[Test 2] Querying for similar rules...")
    query = "powershell downloading malware from internet"
    results = await kb.query_similar_rules(query, n_results=1)
    
    if results:
        print(f"Success! Found rule: {results[0].get('title')}")
        assert results[0]['id'] == "rule_123"
    else:
        print("Failed: No rules found.")

    # 3. Test Deduplication
    import uuid
    print("\n[Test 3] Checking report deduplication...")
    content = f"This is a unique report {uuid.uuid4()}"
    is_dup_before = await kb.check_duplicate_report(content)
    print(f"Is Duplicate (Before): {is_dup_before}")
    
    await kb.register_report(content, {"title": "Test Report", "id": "rep_1"})
    print("Registered report.")
    
    is_dup_after = await kb.check_duplicate_report(content)
    print(f"Is Duplicate (After): {is_dup_after}")
    
    assert is_dup_before is False
    assert is_dup_after is True
    print("\nDeduplication logic verified.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test_kb())
