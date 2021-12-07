rule M_Methodology_HTTP_SerializedObject_JavaObj_JRMPClient_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jrmpclientjavarmiregistryregistryjavalangreflectproxyjavarmiserverremoteobjectinvocationhandler"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS5ybWkucmVnaXN0cnkuUmVnaXN0cn|phdmEucm1pLnJlZ2lzdHJ5LlJlZ2lzdHJ5|qYXZhLnJtaS5yZWdpc3RyeS5SZWdpc3Rye)/
		$keyword1 = /(amF2YS5sYW5nLnJlZmxlY3QuUHJveH|phdmEubGFuZy5yZWZsZWN0LlByb3h5|qYXZhLmxhbmcucmVmbGVjdC5Qcm94e)/
		$keyword2 = /(amF2YS5ybWkuc2VydmVyLlJlbW90ZU9iamVjdEludm9jYXRpb25IYW5kbGVy|phdmEucm1pLnNlcnZlci5SZW1vdGVPYmplY3RJbnZvY2F0aW9uSGFuZGxlc|qYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN0SW52b2NhdGlvbkhhbmRsZX)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_JRMPClient_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jrmpclientjavarmiregistryregistryjavalangreflectproxyjavarmiserverremoteobjectinvocationhandler"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 72 6d 69 2e 72 65 67 69 73 74 72 79 2e 52 65 67 69 73 74 72 79}
		$keyword1 = { 6a 61 76 61 2e 6c 61 6e 67 2e 72 65 66 6c 65 63 74 2e 50 72 6f 78 79}
		$keyword2 = { 6a 61 76 61 2e 72 6d 69 2e 73 65 72 76 65 72 2e 52 65 6d 6f 74 65 4f 62 6a 65 63 74 49 6e 76 6f 63 61 74 69 6f 6e 48 61 6e 64 6c 65 72}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1])
}
