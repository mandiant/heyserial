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
YSoSerial.NET v1.34 payload generation. Run on Windows from the ./utils directory. https://github.com/pwntester/ysoserial.net

### utils/generate_payloads.sh
YSoSerial payload generation. Run on Linux from the ./utils directory. https://github.com/frohoff/ysoserial

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
