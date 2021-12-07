rule M_Methodology_HTTP_SerializedObject_JavaObj_C3P0_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: c3p0commchangev2c3p0poolbackeddatasourceabstractpoolbackeddatasourcepoolbackeddatasourcebasecommchangev2namingreferenceindirectorreferenceserializedb"
	strings:
		$objheader="rO"
		$keyword0 = /(Y29tLm1jaGFuZ2UudjIuYzNwMC5Qb29sQmFja2VkRGF0YVNvdXJjZ|NvbS5tY2hhbmdlLnYyLmMzcDAuUG9vbEJhY2tlZERhdGFTb3VyY2|jb20ubWNoYW5nZS52Mi5jM3AwLlBvb2xCYWNrZWREYXRhU291cmNl)/
		$keyword1 = /(QWJzdHJhY3RQb29sQmFja2VkRGF0YVNvdXJjZ|Fic3RyYWN0UG9vbEJhY2tlZERhdGFTb3VyY2|BYnN0cmFjdFBvb2xCYWNrZWREYXRhU291cmNl)/
		$keyword2 = /(UG9vbEJhY2tlZERhdGFTb3VyY2VCYXNl|Bvb2xCYWNrZWREYXRhU291cmNlQmFzZ|Qb29sQmFja2VkRGF0YVNvdXJjZUJhc2)/
		$keyword3 = /(Y29tLm1jaGFuZ2UudjIubmFtaW5nLlJlZmVyZW5jZUluZGlyZWN0b3|NvbS5tY2hhbmdlLnYyLm5hbWluZy5SZWZlcmVuY2VJbmRpcmVjdG9y|jb20ubWNoYW5nZS52Mi5uYW1pbmcuUmVmZXJlbmNlSW5kaXJlY3Rvc)/
		$keyword4 = /(UmVmZXJlbmNlU2VyaWFsaXplZG|JlZmVyZW5jZVNlcmlhbGl6ZWRi|SZWZlcmVuY2VTZXJpYWxpemVkY)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_C3P0_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: c3p0commchangev2c3p0poolbackeddatasourceabstractpoolbackeddatasourcepoolbackeddatasourcebasecommchangev2namingreferenceindirectorreferenceserializedb"
	strings:
		$objheader={ac ed}
		$keyword0 = { 63 6f 6d 2e 6d 63 68 61 6e 67 65 2e 76 32 2e 63 33 70 30 2e 50 6f 6f 6c 42 61 63 6b 65 64 44 61 74 61 53 6f 75 72 63 65}
		$keyword1 = { 41 62 73 74 72 61 63 74 50 6f 6f 6c 42 61 63 6b 65 64 44 61 74 61 53 6f 75 72 63 65}
		$keyword2 = { 50 6f 6f 6c 42 61 63 6b 65 64 44 61 74 61 53 6f 75 72 63 65 42 61 73 65}
		$keyword3 = { 63 6f 6d 2e 6d 63 68 61 6e 67 65 2e 76 32 2e 6e 61 6d 69 6e 67 2e 52 65 66 65 72 65 6e 63 65 49 6e 64 69 72 65 63 74 6f 72}
		$keyword4 = { 52 65 66 65 72 65 6e 63 65 53 65 72 69 61 6c 69 7a 65 64 62}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
