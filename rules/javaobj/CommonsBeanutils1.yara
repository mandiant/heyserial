rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsBeanutils1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonsbeanutils1javautilpriorityqueueorgapachecommonsbeanutilsbeancomparatorcomparablecomparatorcomsunorgapachexalaninternalxsltctraxtemplatesimpl"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLlByaW9yaXR5UXVldW|phdmEudXRpbC5Qcmlvcml0eVF1ZXVl|qYXZhLnV0aWwuUHJpb3JpdHlRdWV1Z)/
		$keyword1 = /(b3JnLmFwYWNoZS5jb21tb25zLmJlYW51dGlsc|9yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbH|vcmcuYXBhY2hlLmNvbW1vbnMuYmVhbnV0aWxz)/
		$keyword2 = /(QmVhbkNvbXBhcmF0b3|JlYW5Db21wYXJhdG9y|CZWFuQ29tcGFyYXRvc)/
		$keyword3 = /(Q29tcGFyYWJsZUNvbXBhcmF0b3|NvbXBhcmFibGVDb21wYXJhdG9y|Db21wYXJhYmxlQ29tcGFyYXRvc)/
		$keyword4 = /(Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wb|NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcG|jb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBs)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_CommonsBeanutils1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: commonsbeanutils1javautilpriorityqueueorgapachecommonsbeanutilsbeancomparatorcomparablecomparatorcomsunorgapachexalaninternalxsltctraxtemplatesimpl"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 50 72 69 6f 72 69 74 79 51 75 65 75 65}
		$keyword1 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 62 65 61 6e 75 74 69 6c 73}
		$keyword2 = { 42 65 61 6e 43 6f 6d 70 61 72 61 74 6f 72}
		$keyword3 = { 43 6f 6d 70 61 72 61 62 6c 65 43 6f 6d 70 61 72 61 74 6f 72}
		$keyword4 = { 63 6f 6d 2e 73 75 6e 2e 6f 72 67 2e 61 70 61 63 68 65 2e 78 61 6c 61 6e 2e 69 6e 74 65 72 6e 61 6c 2e 78 73 6c 74 63 2e 74 72 61 78 2e 54 65 6d 70 6c 61 74 65 73 49 6d 70 6c}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
