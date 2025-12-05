# Multi-Agent SIEM Framework - Web Interface Setup Guide

This guide details how to set up and run the new Web Dashboard (Frontend) and API Backend for the Multi-Agent SIEM Framework.

## Prerequisites

- **Python 3.10+**
- **Node.js 18+** (and `npm`)
- **Git**

## 1. Backend Setup (API)

The backend is built with **FastAPI** and handles agent orchestration, SIEM integration, and data persistence.

### 1.1. Install Dependencies

Navigate to the project root and install the required Python packages.

```bash
cd multi-agent-siem-framework
pip install -r requirements.txt
```

**Note:** If `requirements.txt` is missing some new packages, install them manually:

```bash
pip install fastapi uvicorn[standard] python-multipart python-dotenv pyyaml langchain langchain-community langchain-google-genai langchain-openai paramiko requests
```

### 1.2. Environment Configuration

Create a `.env` file in the project root (`multi-agent-siem-framework/.env`) with the following keys:

```ini
# --- LLM Providers ---
# Google Gemini (Required for Extractor/Evaluator)
GOOGLE_API_KEY=your_google_api_key

# Cerebras (Required for RuleGen/AttackGen - Llama 3)
CEREBRAS_API_KEY=your_cerebras_api_key

# OpenAI (Optional fallback)
OPENAI_API_KEY=your_openai_api_key

# --- SIEM Integration (Splunk) ---
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USER=admin
SPLUNK_PASSWORD=your_splunk_password
SPLUNK_VERIFY_SSL=false

# --- Attack Simulation (SSH to Windows VM) ---
SSH_HOST=192.168.1.100
SSH_PORT=22
SSH_USER=administrator
SSH_PASSWORD=your_ssh_password
# SSH_KEY_PATH=path/to/private/key (Optional, if using key auth)
```

### 1.3. Run the Backend Server

Start the FastAPI server using Uvicorn.

```bash
# Run from the project root
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

- The API will be available at: `http://localhost:8000`
- API Documentation (Swagger UI): `http://localhost:8000/docs`

---

## 2. Frontend Setup (Dashboard)

The frontend is a **Next.js** application located in the `web/` directory.

### 2.1. Install Dependencies

Navigate to the `web` directory and install Node.js dependencies.

```bash
cd web
npm install
```

### 2.2. Configuration

The frontend is configured to talk to `http://localhost:8000` by default.
If you need to change this, check `web/src/lib/api.ts`.

### 2.3. Run the Development Server

Start the Next.js development server.

```bash
npm run dev
```

- The Dashboard will be available at: `http://localhost:3000`

---

## 3. Usage Guide

1.  **Open the Dashboard**: Go to `http://localhost:3000`.
2.  **Check Status**: Ensure "Active Agents" shows **4/4** (or all green).
3.  **Run Pipeline**:
    *   Click the **"Run Pipeline"** button in the top right.
    *   This will trigger the full workflow:
        1.  **Extraction**: Extract TTPs from the sample CTI report.
        2.  **RuleGen**: Generate Sigma rules.
        3.  **AttackGen**: Generate attack commands (PowerShell).
        4.  **Verification**: Execute the attack via SSH and verify detection in Splunk.
        5.  **Evaluation**: Score the rule quality.
4.  **View Results**:
    *   **Latest Threat Detection**: Shows if the attack was **DETECTED** or **MISSED**.
    *   **Logs**: View real-time system logs and debugging info.
    *   **Agents Page**: View detailed status of each agent.

## 4. Troubleshooting

- **Backend 500 Errors**: Check the terminal running `uvicorn` for Python tracebacks.
- **Empty Logs**: Ensure `logs/system.log` exists and is writable.
- **Attack Execution Failed**:
    - Check SSH credentials in `.env`.
    - Ensure the Windows VM is reachable and has OpenSSH Server installed.
    - Check `logs/system.log` for "Attack execution failed" messages.
- **Splunk Connection Failed**:
    - Ensure Splunk Management Port (8089) is open.
    - Check credentials in `.env`.
