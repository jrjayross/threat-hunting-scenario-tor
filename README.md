<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jrjayross/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched DeviceFileEvents for ANY file that had the string”tor” in it and discovered what looks like the user “jaysoclab” downloaded a tor installer and did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2026-02-20T17:36:52.7583013Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName =="jr-win11vm"
| where FileName contains "tor" and InitiatingProcessAccountName == "jaysoclab"
| where TimeGenerated >= datetime('2026-02-20T17:36:52.7583013Z')
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1217" height="293" alt="Screenshot 1" src="https://github.com/user-attachments/assets/7844c41b-2686-4f02-b8e4-df3df00decb8" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.6.exe”. Based on the logs returned at 2026-02-22T02:25:10.440132Z an employee on the “jr-win11vm” device ran the file tor-browser-windows-x86_64-portable-15.0.6.exe from their downloads folder using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "jr-win11vm"
| where FileName =~ "tor-browser-windows-x86_64-portable-15.0.6.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, ProcessCommandLine
| order by TimeGenerated desc


```
<img width="1168" height="132" alt="screenshot 2" src="https://github.com/user-attachments/assets/a4810690-2b95-47f1-a604-b9c5609f7c3b" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user actually opened the Tor browser. There was evidence that they did open it at this time: 2026-02-20T17:46:08.7150229Z
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned after.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jr-win11vm"
| where ProcessCommandLine has_any("tor.exe","firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 

```<img width="1181" height="434" alt="Screenshot 3" src="https://github.com/user-attachments/assets/fc49220e-6e78-4599-8944-1407be9286b0" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indications of the user utilizing Tor browser to establish a connection using any of the known ports. At 2026-02-20T17:48:03.4182959Z, the virtual machine jr-win11vm shows that the user account “jaysoclab” successfully initiated a network connection using tor.exe, connecting out to the external IP address 94.23.76.244 over port 9001, indicating active TOR network communication from the host.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jr-win11vm"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

```
<img width="1188" height="94" alt="Screenshot 5" src="https://github.com/user-attachments/assets/9565bed1-232c-48fc-84b6-6d51ff794d3d" />
<img width="1189" height="374" alt="Screenshot 4" src="https://github.com/user-attachments/assets/8d77d20b-e331-4755-a664-5fb4aabd48c5" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-20T17:36:52.7583013Z`
- **Event:** The user "jaysoclab" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-20T17:39:58.7143263Z`
- **Event:** The user "jaysoclab" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-20T17:46:08.7150229Z`
- **Event:** User "jaysoclab" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-20T17:48:03.4182959Z`
- **Event:** A network connection to IP `94.23.76.244` on port `9001` by user "jaysoclab" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-20T17:52:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2026-02-20T17:52:08Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "jaysoclab" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-22T02:25:10.440132Z`
- **Event:** The user "jaysoclab" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "jaysoclab" on the "jr-win11vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jr-win11vm` by the user `jaysoclab`. The device was isolated, and the user's direct manager was notified.

---
