# Installation Guide

This guide provides step-by-step instructions for setting up the THREATWISE framework.

## System Requirements

### Hardware
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 10GB free space

### Software
- **Python**: 3.10 or higher
- **Node.js**: 18.x or higher (for web dashboard)
- **Git**: Latest version
- **Optional**: Splunk Enterprise 8.x+, Windows 10+ (for SIEM verification)

---

## Backend Setup

### 1. Clone Repository

```bash
git clone https://github.com/vytr09/multi-agent-siem-framework.git
cd multi-agent-siem-framework
```

### 2. Create Virtual Environment

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Expected time**: 2-3 minutes

### 4. Configure Environment Variables

```bash
# Copy template
cp .env.example .env

# Edit .env file with your credentials
```

**Required variables:**
- `GEMINI_API_KEY`: Google Gemini API key
- `CEREBRAS_API_KEY`: Cerebras API key (for Llama models)
- `OPENAI_API_KEY`: OpenAI API key (optional)

**Optional variables (for SIEM integration):**
- `SPLUNK_HOST`, `SPLUNK_USER`, `SPLUNK_PASSWORD`
- `SSH_HOST`, `SSH_USER`, `SSH_PASSWORD`

See [CONFIGURATION.md](CONFIGURATION.md) for detailed variable descriptions.

### 5. Initialize Knowledge Base

```bash
# Download MITRE ATT&CK data
python scripts/download_mitre.py

# Optional: Populate with sample rules
python scripts/populate_mitre_kb.py
```

### 6. Verify Installation

```bash
# Run health check
python -c "from core.langchain_orchestrator import LangChainOrchestrator; print('Installation successful')"
```

---

## Frontend Setup (Optional)

The web dashboard provides a visual interface for monitoring pipeline execution.

### 1. Install Dependencies

```bash
cd web
npm install
```

**Expected time**: 1-2 minutes

### 2. Configure Environment

```bash
cp .env.example .env.local
```

Edit `.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### 3. Start Development Server

```bash
npm run dev
```

Dashboard will be available at `http://localhost:3000`

---

## Optional: SIEM Integration Setup

### Splunk Enterprise Configuration

**1. Install Splunk Universal Forwarder on Windows test machine**

```powershell
# Download from https://www.splunk.com/
.\splunkforwarder-9.x-x64-release.msi

# Configure forwarding
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk add forward-server <SPLUNK_HOST>:9997
.\splunk add monitor C:\Windows\System32\winevt\Logs\Security.evtx
```

**2. Enable Splunk API**

```bash
# On Splunk server
$SPLUNK_HOME/bin/splunk enable webserver -auth admin:changeme
```

**3. Create API user**
- Navigate to Settings > Access controls > Users
- Create user with `can_search` role
- Generate authentication token

### SSH Access Configuration

**On Windows test machine:**

```powershell
# Enable OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server

# Start service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

**Configure SSH key (recommended):**

```bash
# On orchestrator machine
ssh-keygen -t ed25519 -f ~/.ssh/threatwise_key
ssh-copy-id -i ~/.ssh/threatwise_key.pub user@<SSH_HOST>

# Update .env
SSH_KEY_PATH=/path/to/threatwise_key
```

---

## Running the System

### Start Backend API

```bash
cd api
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Start Web Dashboard

```bash
cd web
npm run dev
```

### Execute Pipeline via CLI

```bash
python scripts/run_agents.py --report data/datasets/sample_report.txt
```

---

## Troubleshooting

### Common Issues

**1. ImportError: No module named 'langchain'**
```bash
# Ensure virtual environment is activated
pip install -r requirements.txt
```

**2. ChromaDB connection error**
```bash
# ChromaDB creates database automatically
# Check disk space and permissions
```

**3. Splunk API authentication failed**
```bash
# Verify credentials
curl -u admin:password https://<SPLUNK_HOST>:8089/services/auth/login
```

**4. SSH connection refused**
```bash
# Check if SSH service is running
# Windows: Get-Service sshd
# Linux: systemctl status ssh
```

For more issues, see [docs/troubleshooting.md](docs/troubleshooting.md).

---

## Next Steps

- Read [CONFIGURATION.md](CONFIGURATION.md) for detailed configuration options
- See [Quick Start](README.md#quick-start) for usage examples
- Review [docs/agents.md](docs/agents.md) for agent-specific configuration
