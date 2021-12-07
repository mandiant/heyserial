# HEY SERIAL!
**Author:**         Alyssa Rahman @ramen0x3f

**Created:**        2021-10-27

**Last Updated:**   2021-12-02

<INSERT BLOG LINK>

### Description
Programmatically create hunting rules for deserialization exploitation with multiple

- keywords (e.g. cmd.exe)
- gadget chains (e.g. CommonsCollection)
- object types (e.g. ViewState, Java, Python Pickle, PHP)
- encodings (e.g. Base64, raw)
- rule types (e.g. Snort, Yara)

### Disclaimer
Rules generated by this tool are intended for hunting/research purposes and are not designed for high fidelity/blocking purposes.

Please *test thoroughly* before deploying to any production systems.

The Yara rules are primarily intended for scanning web server logs. Some of the "object prefixes" are only 2 bytes long, so they can make large scans a bit slow. _(Translation: please don't drop them all into VT Retrohunt.)_

### Usage
Help:
```python3 heyserial.py -h```

Examples:
```
python3 heyserial.py -c 'ExampleChain::condition1+condition2' -t JavaObj
python3 heyserial.py -k cmd.exe whoami 'This file cannot be run in DOS mode'
python3 heyserial.py -k Process.Start -t NETViewState -e base64 "base64+utf16le"
```

# Utils

### utils/checkyoself.py
This is a tool to automate bulk testing of Snort and Yara rules on a variety of sample files. 

Usage:
```python3 checkyoself.py [-y rules.yara] [-s rules.snort] [-o file_output_prefix] [--matches] [--misses] -d malware.exe malware.pcap```

Examples:
```python3 checkyoself.py -y rules/javaobj -s rules/javaobj -d payloads/javaobj pcaps --misses -o java_misses```

### utils/generate_payloads.ps1
YSoSerial.NET v1.34 payload generation. Run on Windows from the ./utils directory. 

- Source: https://github.com/pwntester/ysoserial.net
- License: ysoserial.net_LICENSE.txt

### utils/generate_payloads.sh
YSoSerial payload generation. Run on Linux from the ./utils directory. 

- Source: https://github.com/frohoff/ysoserial
- License: ysoserial_LICENSE.txt

### utils/install_snort.sh
Installing Snort on a Debian based system was a bit finnicky for me, so I wrote my install notes here. 

_Use at your own risk *in a VM* that *you have snapshotted recently*._

### utils/server.py
Simple Python script that runs an HTTP server on 127.0.0.1:12345 and accepts POST requests. 

Handy for generating test PCAPs. 

# License
Copyright (C) 2021 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

# Contributing
Check out the Developers' guide (DEVELOPERS.md) for more details on extending HeySerial!

# Prior Work/Related Resources
Tools
- [Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet) – @GrrrDog
- [Ysoserial](https://github.com/frohoff/ysoserial) - @frohoff 
- [Ysoserial (forked)](https://github.com/wh1t3p1g/ysoserial) - @wh1t3p1g
- [Ysoserial.NET](https://github.com/pwntester/ysoserial.net) and [v2 branch](https://github.com/pwntester/ysoserial.net/tree/v2) - @pwntester 
- [ViewGen](https://github.com/0xacb/viewgen) – 0xacb

Vulnerabilities
- Exchange ([CVE-2021-42321](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42321))
- Zoho ManageEngine ([CVE-2020-10189](https://nvd.nist.gov/vuln/detail/CVE-2020-10189))
- Jira ([CVE-2020-36239](https://oxalis.io/atlassian-jira-data-centers-critical-vulnerability-what-you-need-to-know/))
- Telerik ([CVE-2019-18935](https://bishopfox.com/blog/cve-2019-18935-remote-code-execution-in-telerik-ui))
- C1 CMS ([CVE-2019-18211](https://medium.com/@frycos/yet-another-net-deserialization-35f6ce048df7))
- Jenkins ([CVE-2016-9299](https://nvd.nist.gov/vuln/detail/CVE-2016-9299))
- [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) – @breenmachine, FoxGloveSecurity (2015) 

Talks and Write-Ups
- [This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits](https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits) – Chris Glyer, Dan Perez, Sarah Jones, Steve Miller (2020)
- [Deep Dive into .NET ViewState deserialization and its exploitation](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817) – Swapneil Dash (2019)
- [Exploiting Deserialization in ASP.NET via ViewState](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/) – Soroush Dalili (2019)
- [Use of Deserialization in .NET Framework Methods and Classes](https://research.nccgroup.com/wp-content/uploads/2020/07/whitepaper-new.pdf) – Soroush Dalili(2018)
- [Friday the 13th, JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) – Alvaro Muños and Oleksandr Mirosh (2017)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com/2017/04/exploiting-net-managed-dcom.html) – James Forshaw, Project Zero (2017)
- [Java Unmarshaller Security](https://github.com/frohoff/marshalsec/blob/master/marshalsec.pdf) – Moritz Bechler (2017)
- [Deserialize My Shorts](https://www.slideshare.net/frohoff1/deserialize-my-shorts-or-how-i-learned-to-start-worrying-and-hate-java-object-deserialization) – Chris Frohoff (2016)
- [Pwning Your Java Messaging with Deserialization Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf) – Matthias Kaiser (2016)
- [Journey from JNDI/LDAP Manipulation to Remote Code Execution Dream Land](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf) – Alvaro Muños and Oleksandr Mirosh (2016)
- [Marshalling Pickles](https://www.youtube.com/watch?v=KSA7vUkXGSg) – Chris Frohoff and Gabriel Lawrence (2015)
- [Are you my Type? Breaking .NET Through Serialization](https://github.com/VulnerableGhost/.Net-Sterilized--Deserialization-Exploitation/blob/master/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf) – James Forshaw (2012)
- [A Spirited Peek into ViewState](https://deadliestwebattacks.com/2011/05/13/a-spirited-peek-into-viewstate-part-i/) – Mike Shema (2011)
