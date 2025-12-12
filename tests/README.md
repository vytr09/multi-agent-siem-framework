# Test Suite Documentation

This directory contains the comprehensive test suite for the Multi-Agent SIEM Framework. All tests have been standardized and verified.

## Directory Structure

*   **`unit/`**: Isolated tests for individual agents and core components.
*   **`integration/`**: End-to-end pipeline tests verifying communication between agents.
*   **`benchmark/`**: Scripts for quantitatively evaluating agent performance.
*   **`siem/`**: Tools and tests for SIEM integrations (Splunk/SSH).

## Key Test Files

### 1. Integration Tests (`tests/integration/`)
Run these to verify the entire pipeline flow.

*   **`test_langchain_integration.py`**: **(Primary Test)** Compares "Traditional" vs "LangChain" pipelines. Runs a sample report through Extractor -> RuleGen -> Evaluator.
*   **`test_pipeline_rulegen_comparison.py`**: Side-by-side comparison of the legacy `RuleGen` vs new `LangChainRuleGen` agents, ensuring feature parity (optimization, platform conversion).
*   **`test_pipeline_orc_langchain.py`**: Verifies the `LangChainOrchestrator` correctly manages the feedback loop between agents.
*   **`test_pipeline_feedback_loop.py`**: (Legacy) Verifies the feedback loop logic with a simulated orchestrator.
*   **`test_pipeline_feedback_siem.py`**: **(Advanced)** Full loop with *Real* SIEM integration (requires Splunk connection).
*   **`test_pipeline_attackgen.py`**: Verifies `LangChainAttackGenAgent` output structure and API connectivity.
*   **`test_pipeline_siem_connection.py`**: specific diagnostics for Splunk/SSH connectivity.

### 2. Unit Tests (`tests/unit/`)
Fast checks for individual components.

*   **`test_agent_extractor_simple.py`**: **(Fastest)** Minimal smoke test for Extractor instantiation and basic text processing.
*   **`test_agent_evaluator_flow.py`**: Tests the Evaluator's internal workflow, memory usage, and feedback generation (mocked).
*   **`test_core_memory.py`**: Verifies the custom `MemoryManager` (LangChain replacement) works for persistence and history.
*   **`test_agent_attackgen_real.py`**: **(Slow)** Calls real Gemini API to generate attacks from TTPs.
*   **`test_agent_collector_enhanced.py`**: Tests the Collector's full pipeline (MISP + PDF -> Normalization).
*   **`test_agent_collector_mock.py`**: Mocked version of collector test.
*   **`test_agent_extractor_hybrid.py`**: **(Deep)** Comprehensive test of the Hybrid Extractor (NLP + LLM) with validation logic.

### 3. Benchmarks (`tests/benchmark/`)
Quality evaluation scripts.

*   **`run_attackgen_benchmark.py`**: Uses an LLM Judge to grade generated attack commands.
*   **`run_rulegen_benchmark.py`**: Uses an LLM Judge to grade generated Sigma rules.

### 4. SIEM Tools (`tests/siem/`)
*   **`run_siem_attack_detection.py`**: Orchestrator for executing attacks and verifying them in Splunk (handles query escaping).
*   **`tool_extract_attack_commands.py`**: Utility to extract commands from benchmark results into CSV/JSON/Scripts.
*   **`tool_sigma_to_splunk.py`**: Utility to convert Sigma rules to Splunk queries for testing.

## How to Run Tests

### Prerequisites
1.  **Activate virtual environment**:
    *   Windows: `.venv\Scripts\activate`
    *   Linux/Mac: `source .venv/bin/activate`
2.  **Configure API Keys**:
    *   The tests use the models defined in `config/agents.yaml`.
    *   By default, this project uses **Llama-3.3-70b** via Cerebras. Ensure `.env` has:
        ```bash
        CEREBRAS_API_KEY=your_key_here
        ```
    *   If you change `agents.yaml` to use Google Gemini, ensure `.env` has:
        ```bash
        GEMINI_API_KEY=your_key_here
        ```
    *   For SIEM tests (`tests/siem/` or `tests/integration/test_pipeline_feedback_siem.py`), ensure the following are set in `.env`:
        ```bash
        # Splunk Configuration
        SPLUNK_HOST='...'
        SPLUNK_PORT='8089'
        SPLUNK_USER='...'
        SPLUNK_PASSWORD='...'
        SPLUNK_VERIFY_SSL='false'

        # SSH Configuration (for attack simulation)
        SSH_HOST='...'
        SSH_PORT='22'
        SSH_USER='...'
        SSH_PASSWORD='...'
        SSH_KEY_PATH=
        ```

### Recommended Commands

**1. Quick Health Check**
```bash
python tests/unit/test_agent_extractor_simple.py
```

**2. Verify Core Pipeline (No SIEM)**
```bash
python tests/integration/test_langchain_integration.py
```

**3. Verify Rule Generation Logic**
```bash
python tests/integration/test_pipeline_rulegen_comparison.py
```

**4. Run Benchmarks**
```bash
python tests/benchmark/run_attackgen_benchmark.py
```
