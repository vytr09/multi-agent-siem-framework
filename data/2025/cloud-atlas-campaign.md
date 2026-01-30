---
title: "Cloud Atlas activity in the first half of 2025: what changed"
date: "2025-12-19T10:00:22+00:00"
source: "https://securelist.com/cloud-atlas-h1-2025-campaign/118517/"
crawled_at: "2026-01-19T14:52:55.245325"
---

# Cloud Atlas activity in the first half of 2025: what changed

**Date:** 2025-12-19T10:00:22+00:00
**Source:** [https://securelist.com/cloud-atlas-h1-2025-campaign/118517/](https://securelist.com/cloud-atlas-h1-2025-campaign/118517/)

---

**Author:** Kaspersky GReAT

---

Known since 2014, the Cloud Atlas group targets countries in Eastern Europe and Central Asia. Infections occur via phishing emails containing a malicious document that exploits an old vulnerability in the Microsoft Office Equation Editor process ([CVE-2018-0802](https://securelist.com/<https:/www.cve.org/CVERecord?id=CVE-2018-0802>)) to download and execute malicious code. In this report, we describe the infection chain and tools that the group used in the first half of 2025, with particular focus on previously undescribed implants.

Additional information about this threat, including indicators of compromise, is available to customers of [the Kaspersky Intelligence Reporting Service](https://securelist.com/<https:/www.kaspersky.com/enterprise-security/apt-intelligence-reporting?icid=gl_sl_post-link-apt-reports_sm-team_c6929615b5894647>). Contact: [intelreports@kaspersky.com](https://securelist.com/<mailto:intelreports@kaspersky.com>).

## Technical details

### Initial infection

The starting point is typically a phishing email with a malicious DOC(X) attachment. When the document is opened, a malicious template is downloaded from a remote server. The document has the form of an RTF file containing an exploit for the formula editor, which downloads and executes an HTML Application (HTA) file.  
Fpaylo  

[![Malicious template with the exploit loaded by Word when opening the document](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18182127/cloud-atlas1.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18182127/cloud-atlas1.png>)

Malicious template with the exploit loaded by Word when opening the document

We were unable to obtain the actual RTF template with the exploit. We assume that after a successful infection of the victim, the link to this file becomes inaccessible. In the given example, the malicious RTF file containing the exploit was downloaded from the URL `hxxps://securemodem[.]com?tzak.html_anacid`.

Template files, like HTA files, are located on servers controlled by the group, and their downloading is limited both in time and by the IP addresses of the victims. The malicious HTA file extracts and creates several VBS files on disk that are parts of the VBShower backdoor. VBShower then downloads and installs other backdoors: PowerShower, VBCloud, and CloudAtlas.

This infection chain largely follows the one [previously seen in Cloud Atlas’ 2024 attacks](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/>). The currently employed chain is presented below:

[![Malware execution flow](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18182408/cloud-atlas2.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18182408/cloud-atlas2.png>)

Malware execution flow

Several implants remain the same, with insignificant changes in file names, and so on. You can find more details in our previous article on the following implants:

  * [HTA file](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#hta>)
  * [VBShower::Launcher](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#vbshowerlauncher>)
  * [VBShower::Cleaner](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#vbshowercleaner>)

In this research, we’ll focus on new and updated components.

### VBShower

#### VBShower::Backdoor

Compared to [the previous version](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#vbshowerbackdoor>), the backdoor runs additional downloaded VB scripts in the current context, regardless of the size. A previous modification of this script checked the size of the payload, and if it exceeded 1 MB, instead of executing it in the current context, the backdoor wrote it to disk and used the `wscript` utility to launch it.

#### VBShower::Payload (1)

The script collects information about running processes, including their creation time, caption, and command line. The collected information is encrypted and sent to the C2 server by the parent script (VBShower::Backdoor) via the `v_buff` variable.

[![VBShower::Payload \(1\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18182619/cloud-atlas3.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18182619/cloud-atlas3.png>)

VBShower::Payload (1)

#### VBShower::Payload (2)

The script is used to install the VBCloud implant. First, it downloads a ZIP archive from the hardcoded URL and unpacks it into the `%Public%` directory. Then, it creates a scheduler task named “MicrosoftEdgeUpdateTask” to run the following command line:

wscript.exe /B %Public%\Libraries\MicrosoftEdgeUpdate.vbs

1 | wscript.exe /B %Public%\Libraries\MicrosoftEdgeUpdate.vbs  
---|---  
  
It renames the unzipped file `%Public%\Libraries\v.log` to `%Public%\Libraries\MicrosoftEdgeUpdate.vbs`, iterates through the files in the `%Public%\Libraries` directory, and collects information about the filenames and sizes. The data, in the form of a buffer, is collected in the `v_buff` variable. The malware gets information about the task by executing the following command line:

cmd.exe /c schtasks /query /v /fo CSV /tn MicrosoftEdgeUpdateTask

1 | cmd.exe /c schtasks /query /v /fo CSV /tn MicrosoftEdgeUpdateTask  
---|---  
  
The specified command line is executed, with the output redirected to the TMP file. Both the TMP file and the content of the `v_buff` variable will be sent to the C2 server by the parent script (VBShower::Backdoor).

Here is an example of the information present in the `v_buff` variable:

Libraries: desktop.ini-175| MicrosoftEdgeUpdate.vbs-2299| RecordedTV.library-ms-999| upgrade.mds-32840| v.log-2299|

123456 | Libraries:desktop.ini-175|MicrosoftEdgeUpdate.vbs-2299|RecordedTV.library-ms-999|upgrade.mds-32840|v.log-2299|  
---|---  
  
The file `MicrosoftEdgeUpdate.vbs` is a launcher for VBCloud, which reads the encrypted body of the backdoor from the file `upgrade.mds`, decrypts it, and executes it.

[![VBShower::Payload \(2\) used to install VBCloud](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18183219/cloud-atlas4.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18183219/cloud-atlas4.png>)

VBShower::Payload (2) used to install VBCloud

Almost the same script is used to install the CloudAtlas backdoor on an infected system. The script only downloads and unpacks the ZIP archive to `"%LOCALAPPDATA%"`, and sends information about the contents of the directories `"%LOCALAPPDATA%\vlc\plugins\access"` and `"%LOCALAPPDATA%\vlc"` as output.

In this case, the file renaming operation is not applied, and there is no code for creating a scheduler task.

Here is an example of information to be sent to the C2 server:

vlc: a.xml-969608| b.xml-592960| d.xml-2680200| e.xml-185224|| access: c.xml-5951488|

1234567 | vlc:a.xml-969608|b.xml-592960|d.xml-2680200|e.xml-185224||access:c.xml-5951488|  
---|---  
  
In fact, `a.xml`, `d.xml`, and `e.xml` are the executable file and libraries, respectively, of VLC Media Player. The `c.xml` file is a malicious library used in a DLL hijacking attack, where VLC acts as a loader, and the `b.xml` file is an encrypted body of the CloudAtlas backdoor, read from disk by the malicious library, decrypted, and executed.

[![VBShower::Payload \(2\) used to install CloudAtlas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18183558/cloud-atlas5.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18183558/cloud-atlas5.png>)

VBShower::Payload (2) used to install CloudAtlas

#### VBShower::Payload (3)

This script is the next component for installing CloudAtlas. It is downloaded by VBShower from the C2 server as a separate file and executed after the VBShower::Payload (2) script. The script renames the XML files unpacked by VBShower::Payload (2) from the archive to the corresponding executables and libraries, and also renames the file containing the encrypted backdoor body.

These files are copied by VBShower::Payload (3) to the following paths:

**File** | **Path**  
---|---  
a.xml | %LOCALAPPDATA%\vlc\vlc.exe  
b.xml | %LOCALAPPDATA%\vlc\chambranle  
c.xml | %LOCALAPPDATA%\vlc\plugins\access\libvlc_plugin.dll  
d.xml | %LOCALAPPDATA%\vlc\libvlccore.dll  
e.xml | %LOCALAPPDATA%\vlc\libvlc.dll  
  
Additionally, VBShower::Payload (3) creates a scheduler task to execute the command line: `"%LOCALAPPDATA%\vlc\vlc.exe"`. The script then iterates through the files in the `"%LOCALAPPDATA%\vlc"` and `"%LOCALAPPDATA%\vlc\plugins\access"` directories, collecting information about filenames and sizes. The data, in the form of a buffer, is collected in the `v_buff` variable. The script also retrieves information about the task by executing the following command line, with the output redirected to a TMP file:

cmd.exe /c schtasks /query /v /fo CSV /tn MicrosoftVLCTaskMachine

1 | cmd.exe /c schtasks /query /v /fo CSV /tn MicrosoftVLCTaskMachine  
---|---  
  
Both the TMP file and the content of the `v_buff` variable will be sent to the C2 server by the parent script (VBShower::Backdoor).

[![VBShower::Payload \(3\) used to install CloudAtlas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18183835/cloud-atlas6.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18183835/cloud-atlas6.png>)

VBShower::Payload (3) used to install CloudAtlas

#### VBShower::Payload (4)

This script was previously described as [VBShower::Payload (1)](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#VBShower_Payload_1>).

#### VBShower::Payload (5)

This script is used to check access to various cloud services and executed before installing VBCloud or CloudAtlas. It consistently accesses the URLs of cloud services, and the received HTTP responses are saved to the `v_buff` variable for subsequent sending to the C2 server. A truncated example of the information sent to the C2 server:

GET-https://webdav.yandex.ru| 200| <!DOCTYPE html><html lang="ru" dir="ltr" class="desktop"><head><base href="...

123 | GET-https://webdav.yandex.ru|200|<!DOCTYPE html><html lang="ru" dir="ltr" class="desktop"><head><base href="...  
---|---  
  
[![VBShower::Payload \(5\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184014/cloud-atlas7.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184014/cloud-atlas7.png>)

VBShower::Payload (5)

#### VBShower::Payload (6)

This script was previously described as [VBShower::Payload (2)](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#VBShower_Payload_2>).

#### VBShower::Payload (7)

This is a small script for checking the accessibility of PowerShower’s C2 from an infected system.

[![VBShower::Payload \(7\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184115/cloud-atlas8.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184115/cloud-atlas8.png>)

VBShower::Payload (7)

#### VBShower::Payload (8)

This script is used to install PowerShower, another backdoor known to be employed by Cloud Atlas. The script does so by performing the following steps in sequence:

  1. Creates registry keys to make the console window appear off-screen, effectively hiding it:  

"HKCU\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe"::"WindowPosition"::5122 "HKCU\UConsole\taskeng.exe"::"WindowPosition"::538126692

12 | "HKCU\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe"::"WindowPosition"::5122"HKCU\UConsole\taskeng.exe"::"WindowPosition"::538126692  
---|---  
  
  2. Creates a “MicrosoftAdobeUpdateTaskMachine” scheduler task to execute the command line:  

powershell.exe -ep bypass -w 01 %APPDATA%\Adobe\AdobeMon.ps1

1 | powershell.exe -ep bypass -w 01 %APPDATA%\Adobe\AdobeMon.ps1  
---|---  
  
  3. Decrypts the contents of the embedded data block with XOR and saves the resulting script to the file `"%APPDATA%\Adobe\p.txt"`. Then, renames the file `"p.txt"` to `"AdobeMon.ps1"`.
  4. Collects information about file names and sizes in the path `"%APPDATA%\Adobe"`. Gets information about the task by executing the following command line, with the output redirected to a TMP file:  

cmd.exe /c schtasks /query /v /fo LIST /tn MicrosoftAdobeUpdateTaskMachine

1 | cmd.exe /c schtasks /query /v /fo LIST /tn MicrosoftAdobeUpdateTaskMachine  
---|---  
  

[![VBShower::Payload \(8\) used to install PowerShower](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184552/cloud-atlas9.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184552/cloud-atlas9.png>)

VBShower::Payload (8) used to install PowerShower

The decrypted PowerShell script is disguised as one of the standard modules, but at the end of the script, there is a command to launch the PowerShell interpreter with another script encoded in Base64.

[![Content of AdobeMon.ps1 \(PowerShower\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184641/cloud-atlas10.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184641/cloud-atlas10.png>)

Content of AdobeMon.ps1 (PowerShower)

#### VBShower::Payload (9)

This is a small script for collecting information about the system proxy settings.

[![VBShower::Payload \(9\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184723/cloud-atlas11.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184723/cloud-atlas11.png>)

VBShower::Payload (9)

### VBCloud

On an infected system, VBCloud is represented by two files: a VB script (VBCloud::Launcher) and an encrypted main body (VBCloud::Backdoor). In the described case, the launcher is located in the file `MicrosoftEdgeUpdate.vbs`, and the payload — in `upgrade.mds`.

#### VBCloud::Launcher

The launcher script reads the contents of the `upgrade.mds` file, decodes characters delimited with “%H”, uses the RC4 stream encryption algorithm with a key built into the script to decrypt it, and transfers control to the decrypted content. It is worth noting that the implementation of RC4 uses PRGA (pseudo-random generation algorithm), which is quite rare, since most malware implementations of this algorithm skip this step.

[![VBCloud::Launcher](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184955/cloud-atlas12.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18184955/cloud-atlas12.png>)

VBCloud::Launcher

#### VBCloud::Backdoor

The backdoor performs several actions in a loop to eventually download and execute additional malicious scripts, as [described in the previous research](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#VBCloud_Backdoor>).

#### VBCloud::Payload (FileGrabber)

Unlike VBShower, which uses a global variable to save its output or a temporary file to be sent to the C2 server, each VBCloud payload communicates with the C2 server independently. One of the most commonly used payloads for the VBCloud backdoor is FileGrabber. The script exfiltrates files and documents from the target system [as described before](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#VBCloud_Payload_2>).

The FileGrabber payload has the following limitations when scanning for files:

  * It ignores the following paths: 
    * Program Files
    * Program Files (x86)
    * %SystemRoot%
  * The file size for archiving must be between 1,000 and 3,000,000 bytes.
  * The file’s last modification date must be less than 30 days before the start of the scan.
  * Files containing the following strings in their names are ignored: 
    * “intermediate.txt”
    * “FlightingLogging.txt”
    * “log.txt”
    * “thirdpartynotices”
    * “ThirdPartyNotices”
    * “easylist.txt”
    * “acroNGLLog.txt”
    * “LICENSE.txt”
    * “signature.txt”
    * “AlternateServices.txt”
    * “scanwia.txt”
    * “scantwain.txt”
    * “SiteSecurityServiceState.txt”
    * “serviceworker.txt”
    * “SettingsCache.txt”
    * “NisLog.txt”
    * “AppCache”
    * “backupTest”

[![Part of VBCloud::Payload \(FileGrabber\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18185456/cloud-atlas13.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18185456/cloud-atlas13.png>)

Part of VBCloud::Payload (FileGrabber)

### PowerShower

As mentioned above, PowerShower is installed via one of the VBShower payloads. This script launches the PowerShell interpreter with another script encoded in Base64. Running in an infinite loop, it attempts to access the C2 server to retrieve an additional payload, which is a PowerShell script twice encoded with Base64. This payload is executed in the context of the backdoor, and the execution result is sent to the C2 server via an HTTP POST request.

[![Decoded PowerShower script](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18185552/cloud-atlas14.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18185552/cloud-atlas14.png>)

Decoded PowerShower script

[In previous versions of PowerShower](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#powershower>), the payload created a `sapp.xtx` temporary file to save its output, which was sent to the C2 server by the main body of the backdoor. No intermediate files are created anymore, and the result of execution is returned to the backdoor by a normal call to the `"return"` operator.

#### PowerShower::Payload (1)

This script was previously described as [PowerShower::Payload (2)](https://securelist.com/<https:/securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/#PowerShower_Payload_2>). This payload is unique to each victim.

#### PowerShower::Payload (2)

This script is used for grabbing files with metadata from a network share.

[![PowerShower::Payload \(2\)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18185758/cloud-atlas15.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18185758/cloud-atlas15.png>)

PowerShower::Payload (2)

### CloudAtlas

As described above, the CloudAtlas backdoor is installed via VBShower from a downloaded archive delivered through a DLL hijacking attack. The legitimate VLC application acts as a loader, accompanied by a malicious library that reads the encrypted payload from the file and transfers control to it. The malicious DLL is located at `"%LOCALAPPDATA%\vlc\plugins\access"`, while the file with the encrypted payload is located at `"%LOCALAPPDATA%\vlc\"`.

When the malicious DLL gains control, it first extracts another DLL from itself, places it in the memory of the current process, and transfers control to it. The unpacked DLL uses a byte-by-byte XOR operation to decrypt the block with the loader configuration. The encrypted config immediately follows the key. The config specifies the name of the event that is created to prevent a duplicate payload launch. The config also contains the name of the file where the encrypted payload is located — `"chambranle"` in this case — and the decryption key itself.

[![Encrypted and decrypted loader configuration](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190019/cloud-atlas16.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190019/cloud-atlas16.png>)

Encrypted and decrypted loader configuration

The library reads the contents of the `"chambranle"` file with the payload, uses the key from the decrypted config and the IV located at the very end of the `"chambranle"` file to decrypt it with AES-256-CBC. The decrypted file is another DLL with its size and SHA-1 hash embedded at the end, added to verify that the DLL is decrypted correctly. The DLL decrypted from `"chambranle"` is the main body of the CloudAtlas backdoor, and control is transferred to it via one of the exported functions, specifically the one with ordinal 2.

[![Main routine that processes the payload file](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190217/cloud-atlas17.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190217/cloud-atlas17.png>)

Main routine that processes the payload file

When the main body of the backdoor gains control, the first thing it does is decrypt its own configuration. Decryption is done in a similar way, using AES-256-CBC. The key for AES-256 is located before the configuration, and the IV is located right after it. The most useful information in the configuration file includes the URL of the cloud service, paths to directories for receiving payloads and unloading results, and credentials for the cloud service.

[![Encrypted and decrypted CloudAtlas backdoor config](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190315/cloud-atlas18.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190315/cloud-atlas18.png>)

Encrypted and decrypted CloudAtlas backdoor config

Immediately after decrypting the configuration, the backdoor starts interacting with the C2 server, which is a cloud service, via WebDAV. First, the backdoor uses the MKCOL HTTP method to create two directories: one (`"/guessed/intershop/Euskalduns/"`) will regularly receive a beacon in the form of an encrypted file containing information about the system, time, user name, current command line, and volume information. The other directory (`"/cancrenate/speciesists/"`) is used to retrieve payloads. The beacon file and payload files are AES-256-CBC encrypted with the key that was used for backdoor configuration decryption.

[![HTTP requests of the CloudAtlas backdoor](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190455/cloud-atlas19.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190455/cloud-atlas19.png>)

HTTP requests of the CloudAtlas backdoor

The backdoor uses the HTTP PROPFIND method to retrieve the list of files. Each of these files will be subsequently downloaded, deleted from the cloud service, decrypted, and executed.

[![HTTP requests from the CloudAtlas backdoor](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190549/cloud-atlas20.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190549/cloud-atlas20.png>)

HTTP requests from the CloudAtlas backdoor

The payload consists of data with a binary block containing a command number and arguments at the beginning, followed by an executable plugin in the form of a DLL. The structure of the arguments depends on the type of command. After the plugin is loaded into memory and configured, the backdoor calls the exported function with ordinal 1, passing several arguments: a pointer to the backdoor function that implements sending files to the cloud service, a pointer to the decrypted backdoor configuration, and a pointer to the binary block with the command and arguments from the beginning of the payload.

[![Plugin setup and execution routine](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190634/cloud-atlas21.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190634/cloud-atlas21.png>)

Plugin setup and execution routine

Before calling the plugin function, the backdoor saves the path to the current directory and restores it after the function is executed. Additionally, after execution, the plugin is removed from memory.

#### CloudAtlas::Plugin (FileGrabber)

FileGrabber is the most commonly used plugin. As the name suggests, it is designed to steal files from an infected system. Depending on the command block transmitted, it is capable of:

  * Stealing files from all local disks
  * Stealing files from the specified removable media
  * Stealing files from specified folders
  * Using the selected username and password from the command block to mount network resources and then steal files from them

For each detected file, a series of rules are generated based on the conditions passed within the command block, including:

  * Checking for minimum and maximum file size
  * Checking the file’s last modification time
  * Checking the file path for pattern exclusions. If a string pattern is found in the full path to a file, the file is ignored
  * Checking the file name or extension against a list of patterns

[![Resource scanning](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190733/cloud-atlas22.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190733/cloud-atlas22.png>)

Resource scanning

If all conditions match, the file is sent to the C2 server, along with its metadata, including attributes, creation time, last access time, last modification time, size, full path to the file, and SHA-1 of the file contents. Additionally, if a special flag is set in one of the rule fields, the file will be deleted after a copy is sent to the C2 server. There is also a limit on the total amount of data sent, and if this limit is exceeded, scanning of the resource stops.

[![Generating data for sending to C2](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190907/cloud-atlas23.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18190907/cloud-atlas23.png>)

Generating data for sending to C2

#### CloudAtlas::Plugin (Common)

This is a general-purpose plugin, which parses the transferred block, splits it into commands, and executes them. Each command has its own ID, ranging from 0 to 6. The list of commands is presented below.

  1. **Command ID 0:** Creates, sets and closes named events.
  2. **Command ID 1:** Deletes the selected list of files.
  3. **Command ID 2:** Drops a file on disk with content and a path selected in the command block arguments.
  4. **Command ID 3:** Capable of performing several operations together or independently, including: 
     1. Dropping several files on disk with content and paths selected in the command block arguments
     2. Dropping and executing a file at a specified path with selected parameters. This operation supports three types of launch:
     * Using the WinExec function
     * Using the ShellExecuteW function
     * Using the CreateProcessWithLogonW function, which requires that the user’s credentials be passed within the command block to launch the process on their behalf
  5. **Command ID 4:** Uses the StdRegProv COM interface to perform registry manipulations, supporting key creation, value deletion, and value setting (both DWORD and string values).
  6. **Command ID 5:** Calls the ExitProcess function.
  7. **Command ID 6:** Uses the credentials passed within the command block to connect a network resource, drops a file to the remote resource under the name specified within the command block, creates and runs a VB script on the local system to execute the dropped file on the remote system. The VB script is created at `"%APPDATA%\ntsystmp.vbs"`. The path to launch the file dropped on the remote system is passed to the launched VB script as an argument.

[![Content of the dropped VBS](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18191007/cloud-atlas24.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18191007/cloud-atlas24.png>)

Content of the dropped VBS

#### CloudAtlas::Plugin (PasswordStealer)

This plugin is used to steal cookies and credentials from browsers. This is an extended version of the Common Plugin, which is used for more specific purposes. It can also drop, launch, and delete files, but its primary function is to drop files belonging to the “Chrome App-Bound Encryption Decryption” open-source project onto the disk, and run the utility to steal cookies and passwords from Chromium-based browsers. After launching the utility, several files (`"cookies.txt"` and `"passwords.txt"`) containing the extracted browser data are created on disk. The plugin then reads JSON data from the selected files, parses the data, and sends the extracted information to the C2 server.

[![Part of the function for parsing JSON and sending the extracted data to C2](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18191504/cloud-atlas25.png)](https://securelist.com/<https:/media.kasperskycontenthub.com/wp-content/uploads/sites/43/2025/12/18191504/cloud-atlas25.png>)

Part of the function for parsing JSON and sending the extracted data to C2

#### CloudAtlas::Plugin (InfoCollector)

This plugin is used to collect information about the infected system. The list of commands is presented below.

  1. **Command ID 0xFFFFFFF0:** Collects the computer’s NetBIOS name and domain information.
  2. **Command ID 0xFFFFFFF1:** Gets a list of processes, including full paths to executable files of processes, and a list of modules (DLLs) loaded into each process.
  3. **Command ID 0xFFFFFFF2:** Collects information about installed products.
  4. **Command ID 0xFFFFFFF3:** Collects device information.
  5. **Command ID 0xFFFFFFF4:** Collects information about logical drives.
  6. **Command ID 0xFFFFFFF5:** Executes the command with input/output redirection, and sends the output to the C2 server. If the command line for execution is not specified, it sequentially launches the following utilities and sends their output to the C2 server:

net group "Exchange servers" /domain Ipconfig arp -a

123 | net group "Exchange servers" /domainIpconfigarp -a  
---|---  
  
#### Python script

As mentioned in one of our previous reports, Cloud Atlas uses a custom Python script named `get_browser_pass.py` to extract saved credentials from browsers on infected systems. If the Python interpreter is not present on the victim’s machine, the group delivers an archive that includes both the script and a bundled Python interpreter to ensure execution.

During one of the latest incidents we investigated, we once again observed traces of this tool in action, specifically the presence of the file `"C:\ProgramData\py\pytest.dll"`.

The `pytest.dll` library is called from within `get_browser_pass.py` and used to extract credentials from Yandex Browser. The data is then saved locally to a file named `y3.txt`.

## Victims

According to our telemetry, the identified targets of the malicious activities described here are located in Russia and Belarus, with observed activity dating back to the beginning of 2025. The industries being targeted are diverse, encompassing organizations in the telecommunications sector, construction, government entities, and plants.

## Conclusion

For more than ten years, the group has carried on its activities and expanded its arsenal. Now the attackers have four implants at their disposal (PowerShower, VBShower, VBCloud, CloudAtlas), each of them a full-fledged backdoor. Most of the functionality in the backdoors is duplicated, but some payloads provide various exclusive capabilities. The use of cloud services to manage backdoors is a distinctive feature of the group, and it has proven itself in various attacks.

## Indicators of compromise

**_Note:_**_The indicators in this section are valid at the time of publication._

### File hashes

[0D309C25A835BAF3B0C392AC87504D9E](https://securelist.com/<https:/opentip.kaspersky.com/0d309c25a835baf3b0c392ac87504d9e/results?icid=gl_sl_post-opentip_sm-team_84732fb4913d272a&utm_source=SL&utm_medium=SL&utm_campaign=SL>) протокол (08.05.2025).doc  
[D34AAEB811787B52EC45122EC10AEB08](https://securelist.com/<https:/opentip.kaspersky.com/d34aaeb811787b52ec45122ec10aeb08/results?icid=gl_sl_post-opentip_sm-team_3011a5de627bc4e7&utm_source=SL&utm_medium=SL&utm_campaign=SL>) HTA  
[4F7C5088BCDF388C49F9CAAD2CCCDCC5](https://securelist.com/<https:/opentip.kaspersky.com/4f7c5088bcdf388c49f9caad2cccdcc5/results?icid=gl_sl_post-opentip_sm-team_6f7aed10c5814bb2&utm_source=SL&utm_medium=SL&utm_campaign=SL>) StandaloneUpdate_2020-04-13_090638_8815-145.log:StandaloneUpdate_2020-04-13_090638_8815-145cfcf.vbs  
[5C93AF19EF930352A251B5E1B2AC2519](https://securelist.com/<https:/opentip.kaspersky.com/5c93af19ef930352a251b5e1b2ac2519/results?icid=gl_sl_post-opentip_sm-team_a30b3f08c0aa33e7&utm_source=SL&utm_medium=SL&utm_campaign=SL>) StandaloneUpdate_2020-04-13_090638_8815-145.log:StandaloneUpdate_2020-04-13_090638_8815-145.dat (encrypted)  
[0E13FA3F06607B1392A3C3CAA8092C98](https://securelist.com/<https:/opentip.kaspersky.com/0e13fa3f06607b1392a3c3caa8092c98/results?icid=gl_sl_post-opentip_sm-team_39e2cfac4431a52f&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(1)  
[BC80C582D21AC9E98CBCA2F0637D8993](https://securelist.com/<https:/opentip.kaspersky.com/bc80c582d21ac9e98cbca2f0637d8993/results?icid=gl_sl_post-opentip_sm-team_d83988059a5e9576&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(2)  
[12F1F060DF0C1916E6D5D154AF925426](https://securelist.com/<https:/opentip.kaspersky.com/12f1f060df0c1916e6d5d154af925426/results?icid=gl_sl_post-opentip_sm-team_5e4db7bc81104831&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(3)  
[E8C21CA9A5B721F5B0AB7C87294A2D72](https://securelist.com/<https:/opentip.kaspersky.com/e8c21ca9a5b721f5b0ab7c87294a2d72/results?icid=gl_sl_post-opentip_sm-team_ab743a5a70673904&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(4)  
[2D03F1646971FB7921E31B647586D3FB](https://securelist.com/<https:/opentip.kaspersky.com/2d03f1646971fb7921e31b647586d3fb/results?icid=gl_sl_post-opentip_sm-team_4c8ca300ee57362f&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(5)  
[7A85873661B50EA914E12F0523527CFA](https://securelist.com/<https:/opentip.kaspersky.com/7a85873661b50ea914e12f0523527cfa/results?icid=gl_sl_post-opentip_sm-team_b1a03bc5f0d94c13&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(6)  
[F31CE101CBE25ACDE328A8C326B9444A](https://securelist.com/<https:/opentip.kaspersky.com/f31ce101cbe25acde328a8c326b9444a/results?icid=gl_sl_post-opentip_sm-team_08dd6b0618242fc1&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(7)  
[E2F3E5BF7EFBA58A9C371E2064DFD0BB](https://securelist.com/<https:/opentip.kaspersky.com/e2f3e5bf7efba58a9c371e2064dfd0bb/results?icid=gl_sl_post-opentip_sm-team_8e5fc96404534f2b&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(8)  
[67156D9D0784245AF0CAE297FC458AAC](https://securelist.com/<https:/opentip.kaspersky.com/67156d9d0784245af0cae297fc458aac/results?icid=gl_sl_post-opentip_sm-team_a2c5f41343b816e4&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBShower::Payload(9)  
[116E5132E30273DA7108F23A622646FE](https://securelist.com/<https:/opentip.kaspersky.com/116e5132e30273da7108f23a622646fe/results?icid=gl_sl_post-opentip_sm-team_c81b478b4a30495d&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBCloud::Launcher  
[E9F60941A7CED1A91643AF9D8B92A36D](https://securelist.com/<https:/opentip.kaspersky.com/e9f60941a7ced1a91643af9d8b92a36d/results?icid=gl_sl_post-opentip_sm-team_4e89a774085135d4&utm_source=SL&utm_medium=SL&utm_campaign=SL>) VBCloud::Payload(FileGrabber)  
[718B9E688AF49C2E1984CF6472B23805](https://securelist.com/<https:/opentip.kaspersky.com/718b9e688af49c2e1984cf6472b23805/results?icid=gl_sl_post-opentip_sm-team_dd655526d8984bf7&utm_source=SL&utm_medium=SL&utm_campaign=SL>) PowerShower  
[A913EF515F5DC8224FCFFA33027EB0DD](https://securelist.com/<https:/opentip.kaspersky.com/a913ef515f5dc8224fcffa33027eb0dd/results?icid=gl_sl_post-opentip_sm-team_6b3aa2122bd20511&utm_source=SL&utm_medium=SL&utm_campaign=SL>) PowerShower::Payload(2)  
[BAA59BB050A12DBDF981193D88079232](https://securelist.com/<https:/opentip.kaspersky.com/baa59bb050a12dbdf981193d88079232/results?icid=gl_sl_post-opentip_sm-team_eea2b60078991c31&utm_source=SL&utm_medium=SL&utm_campaign=SL>) chambranle (encrypted)

### Domains and IPs

[billet-ru[.]net](https://securelist.com/<https:/opentip.kaspersky.com/billet-ru.net/?icid=gl_sl_post-opentip_sm-team_69768f2177c3b933&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[mskreg[.]net](https://securelist.com/<https:/opentip.kaspersky.com/mskreg.net/?icid=gl_sl_post-opentip_sm-team_b33b53549e9254e6&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[flashsupport[.]org](https://securelist.com/<https:/opentip.kaspersky.com/flashsupport.org/?icid=gl_sl_post-opentip_sm-team_0e58cac41fa168b1&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[solid-logit[.]com](https://securelist.com/<https:/opentip.kaspersky.com/solid-logit.com/?icid=gl_sl_post-opentip_sm-team_216126a11f6949b2&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[cityru-travel[.]org](https://securelist.com/<https:/opentip.kaspersky.com/cityru-travel.org/?icid=gl_sl_post-opentip_sm-team_cd9b845f9024e89d&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[transferpolicy[.]org](https://securelist.com/<https:/opentip.kaspersky.com/transferpolicy.org/?icid=gl_sl_post-opentip_sm-team_fd699bf6137045c2&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[information-model[.]net](https://securelist.com/<https:/opentip.kaspersky.com/information-model.net/?icid=gl_sl_post-opentip_sm-team_2539cface7d5ada6&utm_source=SL&utm_medium=SL&utm_campaign=SL>)  
[securemodem[.]com](https://securelist.com/<https:/opentip.kaspersky.com/securemodem.com/?icid=gl_sl_post-opentip_sm-team_2536c87c7803ae44&utm_source=SL&utm_medium=SL&utm_campaign=SL>)

