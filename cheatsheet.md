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
> **_Wireshark_** Statistics > Conversations >  TCP Tab
> **_Wireshark_** Statics > Protocol Hierarchy
> **_Wireshark_** File Export Objects > HTML
> **_Wireshark_** Statics > Endpoints
> **_Wireshark_** Statics > Conversions

Wireshark References
> HTTP Filters [here](https://www.wireshark.org/docs/dfref/h/http.html) and [here](https://www.wireshark.org/docs/dfref/h/http2.html)
> HTTPS Filters [here](https://www.wireshark.org/docs/dfref/s/ssl.html)

**HTTPS**
Ports 443, 8443 TCP Encrypted Traffic and in FQDN Format
- Look for traffic *not* encrypted and SSL packet details are empty
- Look for Server Key Exchange and Client key Exchange packet

**Normal HTTPS**
```
Content Type = Handshake
Handshake Protocol: Client Hello
Version: TLS 1.2
Cipher Suites: (11 suites)
Compression Method: (1 method)
```

## Unknown Traffic Threats
- Inspect protocols on network for strange protocols. *IE: IRC Chats, C2 Servers etc*
> **_Wireshark_** Analyze > Enable Protocols

# Webshell Analysis
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

**JPEG PHP Exif**
[exiftool(-k)](http://www.sno.phy.queensu.ca/~phil/exiftool/)
```
<?php
echo "Find file *.jpg :<br />\n List file may be negative :<br />\n";
$exifdata = array();
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator('.')) as $filename)
{
    //echo "$filename<br />\n";
        if      (strpos($filename,".jpg")==true or strpos($filename,".JPG")==true)
        {
                $exif = read_exif_data($filename);
/*1*/   if (isset($exif["Make"])) {
                        $exifdata["Make"] = ucwords(strtolower($exif["Make"]));
                        if (strpos($exifdata["Make"],"/e")==true) echo "$filename<br />\n";
                }
/*2*/   if (isset($exif["Model"])) {
                        $exifdata["Model"] = ucwords(strtolower($exif["Model"]));
                        if (strpos($exifdata["Model"],"/e")==true) echo "$filename<br />\n";
                }
/*3*/   if (isset($exif["Artist"])) {
                        $exifdata["Artist"] = ucwords(strtolower($exif["Artist"]));
                        if (strpos($exifdata["Artist"],"/e")==true) echo "$filename<br />\n";
                }
/*4*/   if (isset($exif["Copyright"])) {
                        $exifdata["Copyright"] = ucwords(strtolower($exif["Copyright"]));
                        if (strpos($exifdata["Copyright"],"/e")==true) echo "$filename<br />\n";
                }
/*5*/   if (isset($exif["ImageDescription"])) {
                        $exifdata["ImageDescription"] = ucwords(strtolower($exif["ImageDescription"]));
                        if (strpos($exifdata["ImageDescription"],"/e")==true) echo "$filename<br />\n";
                }
/*6*/   if (isset($exif["UserComment"])) {
                        $exifdata["UserComment"] = ucwords(strtolower($exif["UserComment"]));
                        if (strpos($exifdata["UserComment"],"/e")==true) echo "$filename<br />\n";
                }
        }
}
echo "Done!";
?>
```

**Linux Commands**
```
find. -type f -name '*.php' -mtime -1
find. -type f -name '*.txt' -mtime -1
find. -type f -name '*.php' | xargs grep -l "eval *("
find. -type f -name '*.txt' | xargs grep -l "eval *("
find. -type f -name '*.php' | xargs grep -l "base64_decode*("
```
```
find . -type f -name '*.php' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
find . -type f -name '*.txt' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
```
**Windows Commands**
[.ps1 scripts](https://github.com/securycore/ThreatHunting)
[Get-FullPathFileStacking.ps1](https://gist.github.com/anonymous/e8ced9c92a689e4cdb67fe0417cd272c)
[Get-TimeDiffFileStacking.ps1](https://gist.github.com/anonymous/dcfa7cb4933b30954737ccbf51024c1a)
[Get-W3WPChildren.ps1](https://gist.github.com/anonymous/140f4455ede789f7c3c3419946d1bd66)

```
get-childitem -recurse include "*.php" | select-string "(mail|fsockopen|pfsockopen|exec\b|system\b|passthru|eval\b|base64_decode)" | %{"$($_.filename):$($_.line)"}| Out-Gridview
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

## Malware Analysis

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
