---
title: "HTB Sherlock Unit42"
date: 2024-06-10T22:02:04+08:00
draft: false
description: "HackTheBox Sherlock Unit42 Writeup"
slug: "HTB+Sherlock+Unit42+Writeup"
tags: ["HackTheBox", "HTB", "Sherlock", "Unit42"]
---

## Sherlock Scenario
In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

## Evidences Overview
```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ unzip -l unit42.zip
Archive:  unit42.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1118208  02-14-2024 08:43   Microsoft-Windows-Sysmon-Operational.evtx
---------                     -------
  1118208                     1 file
```

### EVTX File
EVTX 是 Microsoft Windows 事件記錄檔的副檔名，全稱為 Event Log File。Windows 作業系統使用事件記錄來記錄和存儲各種系統事件、應用程式事件和安全事件。這些事件記錄對於系統管理員和 IT 專業人士來說非常重要，因為它們可以幫助診斷系統問題、監控系統安全和進行故障排除。

使用 Windows 事件檢視器（Event Viewer）可以查看和分析這些日誌檔案。事件檢視器提供了一種圖形化介面，用戶可以瀏覽、篩選和搜尋事件日誌中的資訊。通常，事件日誌包含事件的時間戳、事件 ID、事件來源、事件類型（資訊、警告、錯誤等）以及詳細的事件描述。

此外，事件日誌也可以通過命令列工具（如 `wevtutil`）和程式設計介面（如 `Windows Management Instrumentation, WMI`）來訪問和處理。

### Windows Sysmon
Windows Sysmon（System Monitor）是一種 Windows 系統服務和驅動程式，旨在監視和記錄系統活動以增強操作系統的安全性和監控能力。Sysmon 的主要功能是捕獲詳細的系統事件，這些事件可以幫助系統管理員和安全專業人士識別和分析可疑行為、入侵企圖以及其他安全相關事件。

在 Windows Sysmon 日誌中，每個事件都有一個唯一的事件 ID（Event ID），這有助於識別和分類不同類型的系統活動。Event ID 的說明在 [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) 裡有詳細提到。

以下是這次有的 Event ID：

- `1`: Process creation
- `2`: A process changed a file creation time
- `3`: Network connection
- `5`: Process terminated
- `11`: FileCreate
- `12`: RegistryEvent (Object create and delete)
- `13`: RegistryEvent (Value Set)
- `22`: DNSEvent (DNS query)
- `23`: FileDelete (File Delete archived)
- `26`: FileDeleteDetected (File Delete logged)

### Parse EVTX File
讀取 EVTX 在 Windows 上面應該是最方便的，不過這裡我還是使用 Kali 來解，所以另外找了解析的工具。

我使用跨平台的 [EVTX 解析器 (evtx_dump)](https://github.com/omerbenamram/evtx)，輸出成 JSON 之後，再用 `jq` 來對資料進行疏理。因為是第一次接觸 `jq`，剛好邊學著怎麼用，覺得還挺好用的。

接下來就把 EVTX 轉成 JSON，這裡我多下了 `--dont-show-record-number`，是讓 `evtx_dump` 不要輸出紀錄的編號，不然會讓 `jq` 解析出錯。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ ./evtx_dump --dont-show-record-number -o json -f sysmon.json Microsoft-Windows-Sysmon-Operational.evtx
```

試著把第一筆印出來，基本上我們會關注 `EventID` 是多少，以及 `EventData` 裡面的細節。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -s '.[0]' 
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
      "ProcessGuid": "817BDDF3-3514-65CC-0802-000000001900",
      "ProcessId": 4292,
      "QueryName": "uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com",
      "QueryResults": "type:  5 edge-block-www-env.dropbox-dns.com;::ffff:162.125.81.15;198.51.44.6;2620:4d:4000:6259:7:6:0:1;198.51.45.6;2a00:edc0:6259:7:6::2;198.51.44.70;2620:4d:4000:6259:7:6:0:3;198.51.45.70;2a00:edc0:6259:7:6::4;",                  
      "QueryStatus": "0",
      "RuleName": "-",
      "User": "DESKTOP-887GK2L\\CyberJunkie",
      "UtcTime": "2024-02-14 03:41:25.269"
    },
    "System": {
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "DESKTOP-887GK2L",
      "Correlation": null,
      "EventID": 22,
      "EventRecordID": 118747,
      "Execution": {
        "#attributes": {
          "ProcessID": 3028,
          "ThreadID": 4452
        }
      },
      "Keywords": "0x8000000000000000",
      "Level": 4,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
          "Name": "Microsoft-Windows-Sysmon"
        }
      },
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-18"
        }
      },
      "Task": 22,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2024-02-14T03:41:26.444119Z"
        }
      },
      "Version": 5
    }
  }
}
```

## 問題

### Question 1
> How many Event logs are there with Event ID 11?

把 `EventID` 分別 group_by 起來計算數量，或者更簡單的使用 `grep` 加 `wc -l` 也可以。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -sc 'group_by(.Event.System.EventID) | map({EventID: .[0].Event.System.EventID, count: length}) | .[]'
{"EventID":1,"count":6}
{"EventID":2,"count":16}
{"EventID":3,"count":1}
{"EventID":5,"count":1}
{"EventID":7,"count":15}
{"EventID":10,"count":1}
{"EventID":11,"count":56}
{"EventID":12,"count":14}
{"EventID":13,"count":19}
{"EventID":15,"count":2}
{"EventID":17,"count":7}
{"EventID":22,"count":3}
{"EventID":23,"count":26}
{"EventID":26,"count":2}
```

**Ans: 56**

### Question 2
> Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?

過濾出 `EventID` 為 1 的紀錄，這一筆是裡面最有嫌疑的，`Preventivo24.02.14.exe.exe` 在下載資料夾中由 `explorer.exe` 執行起來，也就代表是被使用者點兩下執行。接著，把檔案的 Hash 拿去查 [VirusTotal](https://www.virustotal.com/gui/file/0cb44c4f8273750fa40497fca81e850f73927e70b13c8f80cdcfee9d1478e6f3)，確定就是惡意程式。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 1)' | jq -s '.[1].Event.EventData'
{
  "CommandLine": "\"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe\" ",
  "Company": "Photo and Fax Vn",
  "CurrentDirectory": "C:\\Users\\CyberJunkie\\Downloads\\",
  "Description": "Photo and vn Installer",
  "FileVersion": "1.1.2",
  "Hashes": "SHA1=18A24AA0AC052D31FC5B56F5C0187041174FFC61,MD5=32F35B78A3DC5949CE3C99F2981DEF6B,SHA256=0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3,IMPHASH=36ACA8EDDDB161C588FCF5AFDC1AD9FA",                                          
  "Image": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "IntegrityLevel": "Medium",
  "LogonGuid": "817BDDF3-311E-65CC-A7AE-1B0000000000",
  "LogonId": "0x1baea7",
  "OriginalFileName": "Fattura 2 2024.exe",
  "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "ParentProcessGuid": "817BDDF3-311F-65CC-0A01-000000001900",
  "ParentProcessId": 1116,
  "ParentUser": "DESKTOP-887GK2L\\CyberJunkie",
  "ProcessGuid": "817BDDF3-3684-65CC-2D02-000000001900",
  "ProcessId": 10672,
  "Product": "Photo and vn",
  "RuleName": "technique_id=T1204,technique_name=User Execution",
  "TerminalSessionId": 1,
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:56.538"
}
```

**Ans: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe**

### Question 3
> Which Cloud drive was used to distribute the malware?

為了找出惡意程式是怎麼進到系統中，先找看看 `EventID` 為 11 且 `TargetFilename` 包含 "Preventivo24" 字串的紀錄，確認是從 Firefox 下載的。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 11) | select(.Event.EventData.TargetFilename | strings | test("Preventivo24"))' | jq -s '.[0].Event.EventData'
{
  "CreationUtcTime": "2024-02-14 03:41:26.459",
  "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "ProcessGuid": "817BDDF3-3514-65CC-0802-000000001900",
  "ProcessId": 4292,
  "RuleName": "-",
  "TargetFilename": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:26.459"
}
```

接下來我們再過濾出 Firefox 發出的 DNS 請求。DNS 查詢的 `EventID` 是 22，然後 Firefox 的 `ProcessId` 是 4292，將兩個條件一起查詢。第一筆紀錄對照時間符合前面 Firefox 下載的時間，所以是 Dropbox。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 22)' | grep 4292 | jq -s '.[].Event.EventData'
{
  "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "ProcessGuid": "817BDDF3-3514-65CC-0802-000000001900",
  "ProcessId": 4292,
  "QueryName": "uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com",
  "QueryResults": "type:  5 edge-block-www-env.dropbox-dns.com;::ffff:162.125.81.15;198.51.44.6;2620:4d:4000:6259:7:6:0:1;198.51.45.6;2a00:edc0:6259:7:6::2;198.51.44.70;2620:4d:4000:6259:7:6:0:3;198.51.45.70;2a00:edc0:6259:7:6::4;",                    
  "QueryStatus": "0",
  "RuleName": "-",
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:25.269"
}
{
  "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "ProcessGuid": "817BDDF3-3514-65CC-0802-000000001900",
  "ProcessId": 4292,
  "QueryName": "d.dropbox.com",
  "QueryResults": "type:  5 d.v.dropbox.com;type:  5 d-edge.v.dropbox.com;162.125.8.20;205.251.192.57;2600:9000:5300:3900::1;",
  "QueryStatus": "0",
  "RuleName": "-",
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:43.924"
}
```

**Ans: dropbox**

#### Question 4
> The initial malicious file time-stamped (a defense evasion technique, where the file creation date is changed to make it appear old) many files it created on disk. What was the timestamp changed to for a PDF file?

修改檔案建立日期的 Event ID 是 2，所以過濾 `EventID` 為 2 且包含 ".pdf" 的紀錄，只有一筆。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 2)' | grep '.pdf' | jq -s '.[].Event.EventData'
{
  "CreationUtcTime": "2024-01-14 08:10:06.029",
  "Image": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "PreviousCreationUtcTime": "2024-02-14 03:41:58.404",
  "ProcessGuid": "817BDDF3-3684-65CC-2D02-000000001900",
  "ProcessId": 10672,
  "RuleName": "technique_id=T1070.006,technique_name=Timestomp",
  "TargetFilename": "C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\TempFolder\\~.pdf",                                                                                                                  
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:58.404"
}
```

**Ans: 2024-01-14 08:10:06**

#### Question 5
> The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.

過濾 `EventID` 是 11、在 `EventData.Image` 中包含 "Preventivo24" 字串，然後存在 "once.cmd" 字串的紀錄。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 11) | select(.Event.EventData.Image | strings | test("Preventivo24"))' | grep 'once.cmd' | jq -s '.[].Event.EventData'
{
  "CreationUtcTime": "2024-02-14 03:41:58.404",
  "Image": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "ProcessGuid": "817BDDF3-3684-65CC-2D02-000000001900",
  "ProcessId": 10672,
  "RuleName": "-",
  "TargetFilename": "C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\once.cmd",                                                                                                     
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:58.404"
}
```

**Ans: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd**

#### Question 6
> The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?

我們可以透過找出由惡意程式發出的 DNS 請求來確認，過濾 `EventID` 是 22 且 `EventData.Image` 包含 "Preventivo24" 字串的紀錄。

``` bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 22) | select(.Event.EventData.Image | strings | test("Preventivo24"))' | jq -s '.[].Event.EventData'
{
  "Image": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "ProcessGuid": "817BDDF3-3684-65CC-2D02-000000001900",
  "ProcessId": 10672,
  "QueryName": "www.example.com",
  "QueryResults": "::ffff:93.184.216.34;199.43.135.53;2001:500:8f::53;199.43.133.53;2001:500:8d::53;",
  "QueryStatus": "0",
  "RuleName": "-",
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:56.955"
}
```

**Ans: www.example.com**

#### Question 7
> Which IP address did the malicious process try to reach out to?

網路連線的 Event ID 是 3，所以過濾 `EventID` 為 3 的紀錄，結果只有一筆，剛好 `Image` 就是惡意程式。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 3)' | jq -s '.[].Event.EventData'
{
  "DestinationHostname": "-",
  "DestinationIp": "93.184.216.34",
  "DestinationIsIpv6": false,
  "DestinationPort": 80,
  "DestinationPortName": "-",
  "Image": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "Initiated": true,
  "ProcessGuid": "817BDDF3-3684-65CC-2D02-000000001900",
  "ProcessId": 10672,
  "Protocol": "tcp",
  "RuleName": "technique_id=T1036,technique_name=Masquerading",
  "SourceHostname": "-",
  "SourceIp": "172.17.79.132",
  "SourceIsIpv6": false,
  "SourcePort": 61177,
  "SourcePortName": "-",
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:57.159"
}
```

**Ans: 93.184.216.34**

#### Question 8
> The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?

終止程序的 Event ID 是 5，因此過濾 `EventID` 為 5 的紀錄，也只有惡意程式這筆。

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Sherlock/Unit42]
└─$ cat sysmon.json | jq -c 'select(.Event.System.EventID == 5)' | jq -s '.[].Event.EventData'
{
  "Image": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "ProcessGuid": "817BDDF3-3684-65CC-2D02-000000001900",
  "ProcessId": 10672,
  "RuleName": "-",
  "User": "DESKTOP-887GK2L\\CyberJunkie",
  "UtcTime": "2024-02-14 03:41:58.795"
}
```

**Ans: 2024-02-14 03:41:58**