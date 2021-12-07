rule M_Methodology_HTTP_SerializedObject_JavaObj_BeanShell1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: beanshell1javautilpriorityqueuecomparatorjavalangreflectproxyhashtablevector"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLlByaW9yaXR5UXVldW|phdmEudXRpbC5Qcmlvcml0eVF1ZXVl|qYXZhLnV0aWwuUHJpb3JpdHlRdWV1Z)/
		$keyword1 = /(Q29tcGFyYXRvc|NvbXBhcmF0b3|Db21wYXJhdG9y)/
		$keyword2 = /(amF2YS5sYW5nLnJlZmxlY3QuUHJveH|phdmEubGFuZy5yZWZsZWN0LlByb3h5|qYXZhLmxhbmcucmVmbGVjdC5Qcm94e)/
		$keyword3 = /(SGFzaHRhYmxl|hhc2h0YWJsZ|IYXNodGFibG)/
		$keyword4 = /(VmVjdG9y|ZlY3Rvc|WZWN0b3)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_BeanShell1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: beanshell1javautilpriorityqueuecomparatorjavalangreflectproxyhashtablevector"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 50 72 69 6f 72 69 74 79 51 75 65 75 65}
		$keyword1 = { 43 6f 6d 70 61 72 61 74 6f 72}
		$keyword2 = { 6a 61 76 61 2e 6c 61 6e 67 2e 72 65 66 6c 65 63 74 2e 50 72 6f 78 79}
		$keyword3 = { 48 61 73 68 74 61 62 6c 65}
		$keyword4 = { 56 65 63 74 6f 72}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
