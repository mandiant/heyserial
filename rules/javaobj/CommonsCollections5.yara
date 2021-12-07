rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections5_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections5javaxmanagementbadattributevalueexpexceptionorgapachecommonscollectionskeyvaluetiedmapentryorgapachecommonscollectionsmaplazymaporgapachecommonscollectionsfunctorschainedtransformerjavalangruntime"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YXgubWFuYWdlbWVudC5CYWRBdHRyaWJ1dGVWYWx1ZUV4cEV4Y2VwdGlvb|phdmF4Lm1hbmFnZW1lbnQuQmFkQXR0cmlidXRlVmFsdWVFeHBFeGNlcHRpb2|qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u)/
		$keyword1 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmtleXZhbHVlLlRpZWRNYXBFbnRye|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cn|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5)/
		$keyword2 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFw|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hc|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYX)/
		$keyword3 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lc|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZX|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVy)/
		$keyword4 = /(amF2YS5sYW5nLlJ1bnRpbW|phdmEubGFuZy5SdW50aW1l|qYXZhLmxhbmcuUnVudGltZ)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections5_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections5javaxmanagementbadattributevalueexpexceptionorgapachecommonscollectionskeyvaluetiedmapentryorgapachecommonscollectionsmaplazymaporgapachecommonscollectionsfunctorschainedtransformerjavalangruntime"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 78 2e 6d 61 6e 61 67 65 6d 65 6e 74 2e 42 61 64 41 74 74 72 69 62 75 74 65 56 61 6c 75 65 45 78 70 45 78 63 65 70 74 69 6f 6e}
		$keyword1 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 6b 65 79 76 61 6c 75 65 2e 54 69 65 64 4d 61 70 45 6e 74 72 79}
		$keyword2 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 6d 61 70 2e 4c 61 7a 79 4d 61 70}
		$keyword3 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 66 75 6e 63 74 6f 72 73 2e 43 68 61 69 6e 65 64 54 72 61 6e 73 66 6f 72 6d 65 72}
		$keyword4 = { 6a 61 76 61 2e 6c 61 6e 67 2e 52 75 6e 74 69 6d 65}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
