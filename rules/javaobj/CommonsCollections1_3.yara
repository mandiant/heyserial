rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections1_3_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections1_3sunreflectannotationannotationinvocationhandlermapproxyorgapachecommonscollectionsmaplazymaporgapachecommonscollectionsfunctorschainedtransformer"
	strings:
		$objheader="rO"
		$keyword0 = /(c3VuLnJlZmxlY3QuYW5ub3RhdGlvbi5Bbm5vdGF0aW9uSW52b2NhdGlvbkhhbmRsZX|N1bi5yZWZsZWN0LmFubm90YXRpb24uQW5ub3RhdGlvbkludm9jYXRpb25IYW5kbGVy|zdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlc)/
		$keyword1 = /(TWFw|1hc|NYX)/
		$keyword2 = /(UHJveH|Byb3h5|Qcm94e)/
		$keyword3 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFw|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hc|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYX)/
		$keyword4 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lc|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZX|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVy)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections1_3_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections1_3sunreflectannotationannotationinvocationhandlermapproxyorgapachecommonscollectionsmaplazymaporgapachecommonscollectionsfunctorschainedtransformer"
	strings:
		$objheader={ac ed}
		$keyword0 = { 73 75 6e 2e 72 65 66 6c 65 63 74 2e 61 6e 6e 6f 74 61 74 69 6f 6e 2e 41 6e 6e 6f 74 61 74 69 6f 6e 49 6e 76 6f 63 61 74 69 6f 6e 48 61 6e 64 6c 65 72}
		$keyword1 = { 4d 61 70}
		$keyword2 = { 50 72 6f 78 79}
		$keyword3 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 6d 61 70 2e 4c 61 7a 79 4d 61 70}
		$keyword4 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 66 75 6e 63 74 6f 72 73 2e 43 68 61 69 6e 65 64 54 72 61 6e 73 66 6f 72 6d 65 72}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
