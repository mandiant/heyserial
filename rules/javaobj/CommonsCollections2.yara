rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections2_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections2javautilpriorityqueueorgapachecommonscollections4comparatorstransformingcomparatorcomparablecomparatorinvokertransformerobject"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLlByaW9yaXR5UXVldW|phdmEudXRpbC5Qcmlvcml0eVF1ZXVl|qYXZhLnV0aWwuUHJpb3JpdHlRdWV1Z)/
		$keyword1 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9y|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvc|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0LmNvbXBhcmF0b3JzLlRyYW5zZm9ybWluZ0NvbXBhcmF0b3)/
		$keyword2 = /(Q29tcGFyYWJsZUNvbXBhcmF0b3|NvbXBhcmFibGVDb21wYXJhdG9y|Db21wYXJhYmxlQ29tcGFyYXRvc)/
		$keyword3 = /(SW52b2tlclRyYW5zZm9ybWVy|ludm9rZXJUcmFuc2Zvcm1lc|JbnZva2VyVHJhbnNmb3JtZX)/
		$keyword4 = /(T2JqZWN0|9iamVjd|PYmplY3)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsCollections2_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonscollections2javautilpriorityqueueorgapachecommonscollections4comparatorstransformingcomparatorcomparablecomparatorinvokertransformerobject"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 50 72 69 6f 72 69 74 79 51 75 65 75 65}
		$keyword1 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 34 2e 63 6f 6d 70 61 72 61 74 6f 72 73 2e 54 72 61 6e 73 66 6f 72 6d 69 6e 67 43 6f 6d 70 61 72 61 74 6f 72}
		$keyword2 = { 43 6f 6d 70 61 72 61 62 6c 65 43 6f 6d 70 61 72 61 74 6f 72}
		$keyword3 = { 49 6e 76 6f 6b 65 72 54 72 61 6e 73 66 6f 72 6d 65 72}
		$keyword4 = { 4f 62 6a 65 63 74}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
