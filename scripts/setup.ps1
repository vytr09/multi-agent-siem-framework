# THREATWISE - Interactive Setup Script
# Run: .\scripts\setup.ps1

param(
    [switch]$SkipFrontend,
    [switch]$SkipDatabase
)

function Show-Banner {
    Write-Host ""
    Write-Host " _____ _  _ ____  ___   _ _____      _____ ____ ___ "  -ForegroundColor Cyan
    Write-Host "|_   _| || | _ \| __| /_\_   _\    / /_ _/ ___| __|" -ForegroundColor Cyan
    Write-Host "  | | | __ |   /|  _| / _ \| | \^/\^/ / | |\_ \|  _| " -ForegroundColor Cyan
    Write-Host "  |_| |_||_|_|_\|___/_/ \_\_|  \_/\_/ |___||__|_____|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Multi-Agent SIEM Framework - Automated Setup Wizard" -ForegroundColor Gray
    Write-Host "  THREAT intelligence extraction + WISE rule synthesis" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Success {
    param($Message)
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-Info {
    param($Message)
    Write-Host "  [i] $Message" -ForegroundColor Cyan
}

function Write-ErrorMsg {
    param($Message)
    Write-Host "  [!] $Message" -ForegroundColor Red
}

function Write-Step {
    param($Step, $Total, $Message)
    Write-Host ""
    Write-Host "[$Step/$Total] $Message" -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor DarkGray
}

function Test-Prerequisites {
    Write-Step 1 6 "Checking prerequisites..."
    
    $allGood = $true
    
    try {
        $pythonVer = python --version 2>&1 | Out-String
        if ($pythonVer -match "Python (\d+\.\d+)") {
            Write-Success "Python found: $($matches[1])"
        }
    } catch {
        Write-ErrorMsg "Python not found"
        $allGood = $false
    }
    
    if (-not $allGood) {
        Write-Host ""
        Write-ErrorMsg "Prerequisites check failed"
        exit 1
    }
}

function Setup-VirtualEnvironment {
    Write-Step 2 6 "Setting up Python virtual environment..."
    Write-Progress -Activity "Setup Progress" -Status "Creating virtual environment..." -PercentComplete 20
    
    if (-not (Test-Path ".venv")) {
        python -m venv .venv
        Write-Success "Virtual environment created"
    } else {
        Write-Info "Virtual environment already exists"
    }
    
    Write-Progress -Activity "Setup Progress" -Status "Activating environment..." -PercentComplete 30
    & .\.venv\Scripts\Activate.ps1
    Write-Success "Virtual environment activated"
}

function Install-Dependencies {
    Write-Step 3 6 "Installing Python dependencies..."
    
    Write-Host "  Upgrading pip..." -ForegroundColor Gray
    python -m pip install --upgrade pip
    
    Write-Host ""
    Write-Host "  Installing requirements..." -ForegroundColor Gray
    python -m pip install -r requirements.txt
    
    Write-Host ""
    Write-Success "Dependencies installed"
}

function Configure-Environment {
    Write-Step 4 6 "Configuring environment..."
    
    if (Test-Path ".env") {
        $overwrite = Read-Host "  .env exists. Overwrite? (y/N)"
        if ($overwrite -ne "y") {
            Write-Info "Skipped .env configuration"
            return
        }
    }
    
    Write-Host ""
    $geminiKey = Read-Host "  Enter Gemini API Key (required)"
    $cerebrasKey = Read-Host "  Enter Cerebras API Key (required)"
    
$envContent = @"
# THREATWISE Configuration
GEMINI_API_KEY='$geminiKey'
CEREBRAS_API_KEY='$cerebrasKey'
OPENAI_API_KEY=''
SPLUNK_HOST='localhost'
SPLUNK_PORT='8089'
SPLUNK_USER='admin'
SPLUNK_PASSWORD=''
SSH_HOST=''
SSH_USER=''
SSH_PASSWORD=''
"@
    
    $envContent | Out-File -FilePath ".env" -Encoding ASCII
    Write-Success ".env file created"
}

function Setup-Frontend {
    if ($SkipFrontend) { return }
    
    Write-Step 5 6 "Setting up web dashboard..."
    
    if (Test-Path "web") {
        Write-Host "  Installing npm packages (this may take 1-2 minutes)..." -ForegroundColor Gray
        Push-Location web
        npm install
        Pop-Location
        Write-Success "npm dependencies installed"
    } else {
        Write-Info "Web directory not found"
    }
}

function Run-HealthCheck {
    Write-Step 6 6 "Running health checks..."
    
    if (Test-Path ".env") {
        Write-Success ".env exists"
    }
    if (Test-Path ".venv") {
        Write-Success "Virtual environment ready"
    }
}

function Start-Services {
    Write-Host ""
    Write-Host "Setup Complete!" -ForegroundColor Green
    Write-Host ""
    
    $start = Read-Host "Start services now? (Y/n)"
    if ($start -ne "n") {
        Write-Host "Starting backend..." -ForegroundColor Cyan
        Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$PWD'; .\.venv\Scripts\Activate.ps1; uvicorn api.main:app --reload"
        
        if ((Test-Path "web") -and -not $SkipFrontend) {
            Start-Sleep 2
            Write-Host "Starting frontend..." -ForegroundColor Cyan
            Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$PWD\web'; npm run dev"
        }
        
        Write-Success "Services started"
    }
}

# Main
try {
    Clear-Host
    Show-Banner
    
    Test-Prerequisites
    Setup-VirtualEnvironment
    Install-Dependencies
    Configure-Environment
    Setup-Frontend
    Run-HealthCheck
    Start-Services
    
} catch {
    Write-ErrorMsg "Setup failed: $_"
    exit 1
}
