rule M_Methodology_HTTP_SerializedObject_JavaObj_Groovy1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: groovy1sunreflectannotationannotationinvocationhandlermapproxyorgcodehausgroovyruntimeconvertedclosureorgcodehausgroovyruntimeconversionhandler"
	strings:
		$objheader="rO"
		$keyword0 = /(c3VuLnJlZmxlY3QuYW5ub3RhdGlvbi5Bbm5vdGF0aW9uSW52b2NhdGlvbkhhbmRsZX|N1bi5yZWZsZWN0LmFubm90YXRpb24uQW5ub3RhdGlvbkludm9jYXRpb25IYW5kbGVy|zdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlc)/
		$keyword1 = /(TWFw|1hc|NYX)/
		$keyword2 = /(UHJveH|Byb3h5|Qcm94e)/
		$keyword3 = /(b3JnLmNvZGVoYXVzLmdyb292eS5ydW50aW1lLkNvbnZlcnRlZENsb3N1cm|9yZy5jb2RlaGF1cy5ncm9vdnkucnVudGltZS5Db252ZXJ0ZWRDbG9zdXJl|vcmcuY29kZWhhdXMuZ3Jvb3Z5LnJ1bnRpbWUuQ29udmVydGVkQ2xvc3VyZ)/
		$keyword4 = /(b3JnLmNvZGVoYXVzLmdyb292eS5ydW50aW1lLkNvbnZlcnNpb25IYW5kbGVy|9yZy5jb2RlaGF1cy5ncm9vdnkucnVudGltZS5Db252ZXJzaW9uSGFuZGxlc|vcmcuY29kZWhhdXMuZ3Jvb3Z5LnJ1bnRpbWUuQ29udmVyc2lvbkhhbmRsZX)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Groovy1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: groovy1sunreflectannotationannotationinvocationhandlermapproxyorgcodehausgroovyruntimeconvertedclosureorgcodehausgroovyruntimeconversionhandler"
	strings:
		$objheader={ac ed}
		$keyword0 = { 73 75 6e 2e 72 65 66 6c 65 63 74 2e 61 6e 6e 6f 74 61 74 69 6f 6e 2e 41 6e 6e 6f 74 61 74 69 6f 6e 49 6e 76 6f 63 61 74 69 6f 6e 48 61 6e 64 6c 65 72}
		$keyword1 = { 4d 61 70}
		$keyword2 = { 50 72 6f 78 79}
		$keyword3 = { 6f 72 67 2e 63 6f 64 65 68 61 75 73 2e 67 72 6f 6f 76 79 2e 72 75 6e 74 69 6d 65 2e 43 6f 6e 76 65 72 74 65 64 43 6c 6f 73 75 72 65}
		$keyword4 = { 6f 72 67 2e 63 6f 64 65 68 61 75 73 2e 67 72 6f 6f 76 79 2e 72 75 6e 74 69 6d 65 2e 43 6f 6e 76 65 72 73 69 6f 6e 48 61 6e 64 6c 65 72}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
