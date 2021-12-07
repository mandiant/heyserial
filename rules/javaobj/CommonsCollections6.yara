rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections6_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections6javautilhashsetorgapachecommonscollectionskeyvaluetiedmapentryorgapachecommonscollectionsmaplazymapchainedtransformer"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLkhhc2hTZX|phdmEudXRpbC5IYXNoU2V0|qYXZhLnV0aWwuSGFzaFNld)/
		$keyword1 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmtleXZhbHVlLlRpZWRNYXBFbnRye|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cn|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5)/
		$keyword2 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFw|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hc|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYX)/
		$keyword3 = /(Q2hhaW5lZFRyYW5zZm9ybWVy|NoYWluZWRUcmFuc2Zvcm1lc|DaGFpbmVkVHJhbnNmb3JtZX)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections6_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections6javautilhashsetorgapachecommonscollectionskeyvaluetiedmapentryorgapachecommonscollectionsmaplazymapchainedtransformer"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 53 65 74}
		$keyword1 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 6b 65 79 76 61 6c 75 65 2e 54 69 65 64 4d 61 70 45 6e 74 72 79}
		$keyword2 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 6d 61 70 2e 4c 61 7a 79 4d 61 70}
		$keyword3 = { 43 68 61 69 6e 65 64 54 72 61 6e 73 66 6f 72 6d 65 72}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1])
}
