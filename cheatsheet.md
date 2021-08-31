# THP Cheat Sheet

This cheatsheet was created during preperation of **eLearnSecurity's Threat Hunting Professional** Certification Exam.

**Useful Links**
- [The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)
- [APT Groups and Operations](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#)

**Open-Source Threat Intelligence Platform**
- [Alien Vault](https://otx.alienvault.com/dashboard/new)
- [US-Cert](https://us-cert.cisa.gov/)
- [MISP-Project](https://www.misp-project.org/)
- [Fireeye Threat Intelligence Reports by Industry](https://www.fireeye.com/current-threats/reports-by-industry.html)
- [Unit 42](https://unit42.paloaltonetworks.com/)

 

# Network Traffic Hunting

## Hunting Tools
- Wireshark - [PA Toolkit Plugin](https://github.com/pentesteracademy/patoolkit)
- [Network Miner](https://www.netresec.com/?page=networkminer)
- [Mandiant IOC Editor](https://www.fireeye.com/services/freeware/ioc-editor.html)


## ARP Theat Hunting

Check packet size, timing etc.

**Normal ARP**

![image](https://user-images.githubusercontent.com/23119194/126065206-2d83fec2-caf6-4b3c-a775-034955182739.png)
![image](https://user-images.githubusercontent.com/23119194/126065208-70493ca7-ce28-4b12-b320-db816107e3c3.png)

**ARP Scanning**

![image](https://user-images.githubusercontent.com/23119194/126065259-03707bb6-cd9d-4465-bb75-fd3413f7e30a.png)
![image](https://user-images.githubusercontent.com/23119194/126067921-04443302-2856-4fa1-a694-f129e6e329bd.png)


## ICMP Threats

**Suspicious ICMP**
- Watch for sprays of ping requests
- Unusual type/codes within packets of the request. 
	- *IE: Time Stamp Requests*

**ICMP Tunnel Detection**
- Compare the Length overall rest packets
- And analyse the payload part
![image](https://user-images.githubusercontent.com/23119194/126067812-07cc405e-5ae1-4219-b4ed-65db5e6f6f71.png)

**ICMP TimeStamp Requests**
![image](https://user-images.githubusercontent.com/23119194/126067820-b965c2b4-34b4-4b18-a0aa-cb7421e501f5.png)

**ICMP Redirect**
- Large Number of ICMP Redirects are sent
- Forece to change 10.100.13.126 Gateway IP'sto  10.100.13.20
![image](https://user-images.githubusercontent.com/23119194/126067869-0b957919-c644-4e0e-92e6-ed6005bedb99.png)


## TCP Threats
**Suspicious TCP**
*3-way handshack: SYN, SYN/ACK, ACK*
- Excessive SYN packets (scanning)
- Usage of different flags
- Single host to multiple ports or single host to multiple nodes (scanning)
- Many TCP SYN packets without corresponding SYN/ACK packets

> [Wireshark TCP Reference](https://www.wireshark.org/docs/dfref/t/tcp.html)
> **_Wireshark_** Edit > Preferences > Protocols > TCP > *(Uncheck Box)*Relative sequence numbers

**TCP RST Attack**

- Spoofed MAC in #12, sents RST Flag
![image](https://user-images.githubusercontent.com/23119194/126068069-4f4b648c-6756-4dc4-b9e6-de0897d17bb4.png)

**SYN Scanning**
Source Port Abnormalities
![image](https://user-images.githubusercontent.com/23119194/126115674-fa0ec1b3-f7e2-445a-acfc-5d0e829cc5a7.png)

Destination Port Abnormalities - Destination port 0 (TCP)
![image](https://user-images.githubusercontent.com/23119194/126115770-f1b91d4a-9415-49fe-aac5-43ecf0333775.png)


**TCP Session Hijacking**

![image](https://user-images.githubusercontent.com/23119194/126068300-051509e0-9fef-4170-a74c-36203e61826a.png)

- #15 TCP Retransmission is displayed because the sequence number and the acknowledgement number of this packet are the same as the ones in packet #11.
- The MAC address of the client (192.168.1.4) in this packet is different than the MAC address that is included in all previous packets related to this host.
- It looks like an attacker has taken over (hijacked) the whole Telnet session. This is also apparent in packet #17, that includes the MAC address of the attacker and the command the attacker issued (uname –a)

**OFT2 - Unknown Traffic**
At the beginning of the TCP Stream, you will see OFT2. OFT2 is AOL instant messaging protocol, OSCAR (Open
System for CommunicAtion in Realtime).
![image](https://user-images.githubusercontent.com/23119194/131216480-b12b78f9-2753-464b-ada6-aed746fd5f33.png)

Wireshark > Analyze > Enable Protocols
![image](https://user-images.githubusercontent.com/23119194/131216496-772c4a9c-e898-402a-8e05-94a0a442a89e.png)

Before
![image](https://user-images.githubusercontent.com/23119194/131216537-56541a15-7615-4846-ab8c-009ea29a1bfe.png)


On one of the packets,  right-click and select Decode As.
A new window will appear titled “Wireshark Decode As…”
![image](https://user-images.githubusercontent.com/23119194/131216558-28f851b5-6901-4938-aae2-359be1794d71.png)

After
![image](https://user-images.githubusercontent.com/23119194/131216564-9ad1cd22-6191-4de6-819d-3ada00c05b18.png)

## DNS Threats
- Port 53, should only be **UDP** not **TCP** (Name Queries)
- DNS traffic should only go to DNS servers
- Should see DNS Responses to DNS Queries
> [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/d/dns.html)
> Look for DNS Queries with no DNS responses or vice versa.
> Zone Tranfers occur over TCP/53

**Zone Transfer**
Query:
![image](https://user-images.githubusercontent.com/23119194/126116442-eba60e8e-415d-4abd-962e-786b2f0dea1d.png)

Response:
![image](https://user-images.githubusercontent.com/23119194/126116649-f7c81bfb-e403-4e7f-996f-3e10919c148d.png)



## HTTP/HTTPS Threats
**HTTP**
Port 80, 8080 - plantext traffic, typically in FQDN format.

- Traffic should *not* be encrypted in common HTTP ports
- Search for URL encoded queries for sql injection (sqlmap, %27 = single quote %20...), lfi-rfi activity
- User-Agent for possible scanners - *IE: sqlmap*
- TCP Spurious Retransmission -> Investigate [TCP Zero Window](https://wiki.wireshark.org/TCP%20ZeroWindow)

**Useful Areas withing Wireshark**
- **_Wireshark_** Statistics > Conversations >  TCP Tab
- **_Wireshark_** Statics > Protocol Hierarchy
- **_Wireshark_** File Export Objects > HTML
- **_Wireshark_** Statics > Endpoints
- **_Wireshark_** Statics > Conversions

Wireshark References
> HTTP Filters [here](https://www.wireshark.org/docs/dfref/h/http.html) and [here](https://www.wireshark.org/docs/dfref/h/http2.html)
> HTTPS Filters [here](https://www.wireshark.org/docs/dfref/s/ssl.html)

**HTTPS**
Ports 443, 8443 TCP Encrypted Traffic and in FQDN Format
- Look for traffic *not* encrypted and SSL packet details are empty
![image](https://user-images.githubusercontent.com/23119194/126209401-13cd1fdc-b1e4-450a-a371-1e9c389e7272.png)

- Look for Server Key Exchange and Client key Exchange packet 
> No "Client Hello"
![image](https://user-images.githubusercontent.com/23119194/126209843-27e8cb26-be49-40a9-9663-ee0faf7e2c54.png)

- The number of new Client Hello messages is abnormal.  (ssl.record.content_type == 22)
> Taking into consideration both the above, it looks like we are dealing with a SSL Renegotiation Attack
![image](https://user-images.githubusercontent.com/23119194/126210256-2a769166-f472-4471-9a45-60b618df7918.png)

- Look for TCP(443) TCP Spurious Retransmission
![image](https://user-images.githubusercontent.com/23119194/131216255-68f3af8e-a48e-40d1-b39c-4868d7fa8761.png)
TCP Spurious Retransmission is when the sending host ‘thinks’ that the receiving host didn’t receive the packet and
sends it again. 

```
**Webshell Analysis**

- Reference suspicious files on servers/web servers
- Look for cmd.exe powershell.exe or eval()
- Analyze IIS and Apache logs
- Use baselines for locating new processes, drivers, intsalled applications, files/services
- Analyze suspicious JPEG images

**Webshell PHP Functions**
> eval()
> base64_decode()
> str_rot13()
> gzinflate()

```


**Linux Commands**
```
> find . –type f –name ‘*.php’ –mtime -1
> find . –type f –name ‘*.txt’ –mtime -1
> find . –type f –name ‘*.php’ | xargs grep –l “eval *(”
> find . –type f –name ‘*.txt’ | xargs grep –l “eval *(”
> find . –type f –name ‘*.php’ | xargs grep –l “base64_decode*(”
> find . –type f –name ‘*.php’ | xargs egrep -i "(mail|fsockopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
> find . -type f -name '*.txt' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("

```

**Windows Commands**
[.ps1 scripts](https://github.com/securycore/ThreatHunting)
[Get-FullPathFileStacking.ps1](https://gist.github.com/anonymous/e8ced9c92a689e4cdb67fe0417cd272c)
[Get-TimeDiffFileStacking.ps1](https://gist.github.com/anonymous/dcfa7cb4933b30954737ccbf51024c1a)
[Get-W3WPChildren.ps1](https://gist.github.com/anonymous/140f4455ede789f7c3c3419946d1bd66)

```
> get-childitem -recurse include "*.php" | select-string "(mail|fsockopen|pfsockopen|exec\b|system\b|passthru|eval\b|base64_decode)" | %{"$($_.filename):$($_.line)"}| Out-Gridview

```

**Webshell Toolkit**
[Log Parser Studio Tool](https://gallery.technet.microsoft.com/office/Log-Parser-Studio-cd458765) - IIS Web Logs



[Loki](https://github.com/loki-project/loki)
> MD5/SHA1/SHA256 hashes
> Yara rules
> Hard/soft filenames based on regular expressions

[NeoPI](https://github.com/Neohapsis/NeoPI)
> Python script - detect obfuscated/encrypted content

[BackdoorMan](https://github.com/cys3c/BackdoorMan)
> Python script - Detect malicious code in **PHP** scripts
> Detects shells via signature database
> Recognize web backdoors
> Use [shellray](https://shellray.com/)/[VirusTotal](https://virustotal.com/) and [UnPHP](http://www.unphp.net/)

[PHP-Malware-Finder](https://github.com/nbs-system/php-malware-finder)
> Find obfuscated code
> Yara Rules

[UnPHP](http://www.unphp.net/)
> Online PHP Obfuscator

[Web Shell Detector](http://www.shelldetector.com/)
> PHP, Perl, ASP and ASPX detection
> Signature database

[NPROCWATCH](http://udurrani.com/0fff/tl.html)
> Display new spawned processes after  NPROCWATCH was executed

*Others*
[Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/)
[Invoke-ExchangeWebShellHunter](https://github.com/FixTheExchange/Invoke-ExchangeWebShellHunter)

## Windows Processes
**SMS.EXE**
- SMSS.EXE is known as the Session Manager. Its responsibility is to create new sessions.
- Session 0 starts csrss.exe and wininit.exe. (OS services)
- Session 1 starts csrss.exe and winlogon.exe. (User session)
-  You will see 1 instance (Session 0) within the process tree. The child instances  of smss.exe which was used to create the other sessions, by copying itself into that new session, will self-terminate.
- Executable Path: %SystemRoot%\System32\smss.exe
- Hunting Tip : Sessions 0 and 1 are normal. Additional sessions may be created by Remote Desktop Protocol (RDP) sessions and Fast User Switching on shared computers. If this does not apply to your environment, then it’s worth checking the additional sessions (if such exist). Remember only 1 instance of smss.exe should be running. 

**csrss.exe**
- CSRSS.EXE is the Client/Server Run Subsystem Process. It is responsible for managing processes and threads, as well as making the Windows API available for other processes. It’s also responsible for mapping drive letters, creating temp files, and handling the shutdown process.
- Runs within Session 0 and 1.
- Will be available for each newly created user session
- Executable Path: %SystemRoot%\System32\csrss.exe
- Hunting Tip : Malware authors can masquerade their malware to appear as this process by hiding in plain sight. They can name the malware as csrss.exe but just misspell it slightly. Examples of this would be cssrs.exe, cssrss.exe, and csrsss.exe. Remember, typically you will see 2 instances of csrss.exe.

**winlogon.exe**
-WINLOGON.EXE is the Windows Logon Process. It is responsible for user logons/logoffs. It launches LogonUI.exe for username and password and passes credentials to LSASS.exe which is verified via AD or local SAM.
- Loads Userinit.exe via Software\Microsoft\Windows NT\CurrentVersion\Winlogon.
- Executable Path: %SystemRoot%\System32\winlogon.exe
- Hunting Tip : The abuse within this process often comes within the different components of the login process. Malware sometimes abuses the SHELL registry value. This value
should be explorer.exe. Another registry key that is abused by malware that works in conjunction with winlogon.exe is Userinit.

**wininit.exe**
- WININIT.EXE is the Windows Initialization Process. It is responsible to launch services.exe, lsass.exe, and lsm.exe in Session 0.
- Executable Path: %SystemRoot%\System32\wininit.exe
- Hunting Tip : You should only see 1 instance of wininit.exe.

**lsm.exe**
- LSM.EXE is the Local Session Manager. It is responsible to work with smss.exe to create, destroy, or manipulate new user sessions.
- Responsible for logon/logoff, shell start/end,lock/unlock desktop to name a few.
- Note: After Windows 7, lsm.exe no longer exists, and it is now a service called lsm.dll.
- Executable Path: %SystemRoot%\System32\lsm.exe
- Hunting Tip : You should only see 1 instance of lsm.exe on Windows 7 machines. You should NOT be seeing this on Windows 8 and beyond. It will be running as a service DLL instead,lsm.dll.

**services.exe**
- SERVICES.EXE is the Service Control Manager. It is responsible for loading services (auto-start) and device drivers into memory.
- Parent to svchost.exe, dllhost.exe, taskhost.exe, spoolsv.exe, etc.
- Services are defined in HKLM\SYSTEM\CurrentControlSet\Services.
- Maintains an in-memory database of service information which can be queried using the built-in Windows tool, sc.exe.
-  After a successful interactive login, services.exe will backup a copy of the registry keys into HKLM\SYSTEM\Select\LastKnownGood which will be known as the Last Known Good Configuration.
- Executable Path: %SystemRoot%\System32\services.exe
- Hunting Tip : You should only see 1 instance of services.exe. This is a protected process which makes it difficult to tamper with.

**lsass.exe**
- LSASS.EXE is the Local Security Authority Subsystem. It is responsible for user authentication and generating access tokens specifying security policies and/or restrictions for the user and the processes spawned in the user session.
- Uses authentication packages within HKLM\System\CurrentControlSet\Control\Lsa to authenticate users.
- Creates security tokens for SAM, AD, and NetLogon.
- Writes to the Security event log.
- Executable Path: %SystemRoot%\System32\lsass.exe
- Hunting Tip : You should only see 1 instance of lsass.exe. This process is commonly attacked and abused by hackers and malware. It is targeted to dump password hashes and is often used to hide in plain sight. You might see different variations of spelling for this process (lass.exe or lsasss.exe), and might even see multiple instances of it, like with Stuxnet malware. 

**svchost.exe**
- SVCHOST.EXE is the Generic Service Host Process. It is responsible for hosting multiple services DLLs into a generic shared service process.
- Each service will have registry entries that include ServiceDll. This will instruct svchost.exe what DLL to use. The entry will also include svchost.exe –k <name>.
- Multiple instances of svchost.exe host will be running, as seen in the screenshot to the right.
- All DLL-based services with the same <name> will share the same svchost.exe process.
- <name> values are found in Software\Microsoft\Windows NT\CurrentVersion\Svchost registry key.
- Each svchost.exe process will run with a unique –k <name>
- Executable Path: %SystemRoot%\System32\svchost.exe
- Hunting Tip : This process is another process that is heavily abused. It can be used to launch malicious services (malware installed as a service). When this is done, (-k) will not be present. This process is often misspelled to hide in plain sight. Another technique used with this process is to place it in different directories, but note that services.exe will not be the parent.
- Hunting Tip2 : When it comes to services, we will need to perform extra  steps to determine whether the service/DLL being loaded by svchost.exe is legitimate or not.
It’s more than just checking for misspellings in svchost.exe, because techniques such as Process Injection and Process Hollowing can attack legitimate services. In these cases,
advanced techniques are required, such as memory analysis.
	
**taskhost.exe**
- TASKHOST.EXE is a generic host process which acts as a host for processes that run from DLLs rather than EXEs. At startup, TASKHOST checks the Services portion of the Registry to construct a list of DLL-based services that it needs to load, and then loads them.
- In Windows 8, this process was renamed to taskhostex.exe.
- In Windows 10, this process was renamed to taskhostw.exe.
- Executable Path: %SystemRoot%\System32\taskhost.exe

**explorer.exe**
- EXPLORER.EXE is the Windows Explorer.
- Explorer.exe is responsible for the user’s desktop and everything that comes with it, including access to files (file browser) and launching files via their file extensions.
- Even if multiple Windows Explorer windows open, only 1 process will be spawned per logged on user.
- Executable Path: %SystemRoot%\explorer.exe
- Hunting Tip : This process is targeted by malware as well. Different techniques will be incorporated, like the ones already mentioned, against this process. They will inject into the process, spawn malware named as explorer.exe, run it from a different folder or misspell it and have it run from the actual folder. Look for instances where explorer has CMD hanging off it or is listening/connected on a network port.
- Hunting Tip : Let’s add more to the checklist shown near the beginning of this section.
• Core Windows processes shouldn’t run from Windows temp locations, or the Recycle Bin, and neither should be communicating to any outbound IPs.
• Check for digital signatures (all Microsoft artifacts should be digitally signed)
• Look for any process that have cmd.exe, wscript.exe, powershell.exe etc. running as a child process.
• Lastly, you’ll need to dig deeper, and that is where memory analysis will come into play to find instances of DLL injection, Process Hollowing, etc.

	
```

**Windows Event Logs**
>Successful Logon (ID 4624)

>Failed Logon (ID 4625)

>Kerberos Authentication (ID 4768)

>Kerberos Service Ticket (ID 4776)

>Assignment of Administrator Rights (ID 4672)

>Unknown username or password (ID 529)

>Account logon time restriction violation (ID 530)

>Account currently disabled (ID 531)

>User account has expired (ID 532)

>User not allowed to logon to the computer (ID 533)

>User has not been granted the requested logon type (ID 534)

>The account's password has expired (ID 535)

>The NetLogon component is not active (ID 536)

>The logon attempt failed for other reasons (ID 537)

>Account lockout (ID 539)

>Log clearing (ID 1102 and 104)


**Detection Tools**

*PE Capture*
[PE Capture Service](http://www.novirusthanks.org/products/pe-capture-service/)

[NoVirusThanks](http://www.novirusthanks.org/products/pe-capture/)

[ProcScan](https://github.com/abhisek/RandomCode/tree/master/Malware/Process)
> Ruby script - x86-only memory analysis

[Meterpeter Payload Detection](https://github.com/DamonMohammadbagher/Meterpreter_Payload_Detection)
> Memory anaylsis for Meterpreter sessions

*Reflective Injection Detection*

[Reflective Injection Detection](https://github.com/papadp/reflective-injection-detection)

[PowershellArsenal](https://github.com/mattifestation/PowerShellArsenal)

*NTQueryInformationThread Detection*

[Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

*Hash Fuzzing*
[SSDeep](https://github.com/ssdeep-project/ssdeep)

*Port Hashing*
[imphash](https://github.com/Neo23x0/ImpHash-Generator) - Generate PE 

*Execution Tracing*
[ShimCacheParser](https://github.com/mandiant/ShimCacheParser)

[AppCompatProcessor](https://github.com/mbevilacqua/appcompatprocessor)

**Memory Analysis**
- [Mandiant's Redline](https://www.fireeye.com/services/freeware/redline.html)
- [Volatility](https://github.com/volatilityfoundation/volatility): [Wiki](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage), [Windows Analysis](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal) and [Memory Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)

## Powershell Tools
[Kansa](https://github.com/davehull/Kansa)
>Incident response, breach hunts, building baselines
> Reference links [here](http://trustedsignal.blogspot.com/search/label/Kansa) and [here](http://www.powershellmagazine.com/2014/07/18/kansa-a-powershell-based-incident-response-framework/)

[PSHunt](https://github.com/Infocyte/PSHunt)
>Scan remote endpoints for IOCS

[NOAH](https://github.com/giMini/NOAH)
