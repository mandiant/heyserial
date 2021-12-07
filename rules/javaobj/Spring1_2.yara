rule M_Methodology_HTTP_SerializedObject_JavaObj_Spring1_2_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: spring1_2orgspringframeworkcoreserializabletypewrappermethodinvoketypeprovidertypeproviderjavalangreflectproxysunreflectannotationannotationinvocationhandlerjavautilhashmap"
	strings:
		$objheader="rO"
		$keyword0 = /(b3JnLnNwcmluZ2ZyYW1ld29yay5jb3JlLlNlcmlhbGl6YWJsZVR5cGVXcmFwcGVy|9yZy5zcHJpbmdmcmFtZXdvcmsuY29yZS5TZXJpYWxpemFibGVUeXBlV3JhcHBlc|vcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuU2VyaWFsaXphYmxlVHlwZVdyYXBwZX)/
		$keyword1 = /(TWV0aG9kSW52b2tlVHlwZVByb3ZpZGVy|1ldGhvZEludm9rZVR5cGVQcm92aWRlc|NZXRob2RJbnZva2VUeXBlUHJvdmlkZX)/
		$keyword2 = /(VHlwZVByb3ZpZGVy|R5cGVQcm92aWRlc|UeXBlUHJvdmlkZX)/
		$keyword3 = /(amF2YS5sYW5nLnJlZmxlY3QuUHJveH|phdmEubGFuZy5yZWZsZWN0LlByb3h5|qYXZhLmxhbmcucmVmbGVjdC5Qcm94e)/
		$keyword4 = /(c3VuLnJlZmxlY3QuYW5ub3RhdGlvbi5Bbm5vdGF0aW9uSW52b2NhdGlvbkhhbmRsZX|N1bi5yZWZsZWN0LmFubm90YXRpb24uQW5ub3RhdGlvbkludm9jYXRpb25IYW5kbGVy|zdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlc)/
		$keyword5 = /(amF2YS51dGlsLkhhc2hNYX|phdmEudXRpbC5IYXNoTWFw|qYXZhLnV0aWwuSGFzaE1hc)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Spring1_2_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: spring1_2orgspringframeworkcoreserializabletypewrappermethodinvoketypeprovidertypeproviderjavalangreflectproxysunreflectannotationannotationinvocationhandlerjavautilhashmap"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6f 72 67 2e 73 70 72 69 6e 67 66 72 61 6d 65 77 6f 72 6b 2e 63 6f 72 65 2e 53 65 72 69 61 6c 69 7a 61 62 6c 65 54 79 70 65 57 72 61 70 70 65 72}
		$keyword1 = { 4d 65 74 68 6f 64 49 6e 76 6f 6b 65 54 79 70 65 50 72 6f 76 69 64 65 72}
		$keyword2 = { 54 79 70 65 50 72 6f 76 69 64 65 72}
		$keyword3 = { 6a 61 76 61 2e 6c 61 6e 67 2e 72 65 66 6c 65 63 74 2e 50 72 6f 78 79}
		$keyword4 = { 73 75 6e 2e 72 65 66 6c 65 63 74 2e 61 6e 6e 6f 74 61 74 69 6f 6e 2e 41 6e 6e 6f 74 61 74 69 6f 6e 49 6e 76 6f 63 61 74 69 6f 6e 48 61 6e 64 6c 65 72}
		$keyword5 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 4d 61 70}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
