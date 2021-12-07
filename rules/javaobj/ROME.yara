rule M_Methodology_HTTP_SerializedObject_JavaObj_ROME_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: romejavautilhashmapcomsunsyndicationfeedimplobjectbeancomsunsyndicationfeedimplcloneablebeanjavautilcollectionsemptysetcomsunorgapachexalaninternalxsltctraxtemplatesimpl"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLkhhc2hNYX|phdmEudXRpbC5IYXNoTWFw|qYXZhLnV0aWwuSGFzaE1hc)/
		$keyword1 = /(Y29tLnN1bi5zeW5kaWNhdGlvbi5mZWVkLmltcGwuT2JqZWN0QmVhb|NvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLk9iamVjdEJlYW|jb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5PYmplY3RCZWFu)/
		$keyword2 = /(Y29tLnN1bi5zeW5kaWNhdGlvbi5mZWVkLmltcGwuQ2xvbmVhYmxlQmVhb|NvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLkNsb25lYWJsZUJlYW|jb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5DbG9uZWFibGVCZWFu)/
		$keyword3 = /(amF2YS51dGlsLkNvbGxlY3Rpb25z|phdmEudXRpbC5Db2xsZWN0aW9uc|qYXZhLnV0aWwuQ29sbGVjdGlvbn)/
		$keyword4 = /(RW1wdHlTZX|VtcHR5U2V0|FbXB0eVNld)/
		$keyword5 = /(Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wb|NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcG|jb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBs)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_ROME_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: romejavautilhashmapcomsunsyndicationfeedimplobjectbeancomsunsyndicationfeedimplcloneablebeanjavautilcollectionsemptysetcomsunorgapachexalaninternalxsltctraxtemplatesimpl"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 4d 61 70}
		$keyword1 = { 63 6f 6d 2e 73 75 6e 2e 73 79 6e 64 69 63 61 74 69 6f 6e 2e 66 65 65 64 2e 69 6d 70 6c 2e 4f 62 6a 65 63 74 42 65 61 6e}
		$keyword2 = { 63 6f 6d 2e 73 75 6e 2e 73 79 6e 64 69 63 61 74 69 6f 6e 2e 66 65 65 64 2e 69 6d 70 6c 2e 43 6c 6f 6e 65 61 62 6c 65 42 65 61 6e}
		$keyword3 = { 6a 61 76 61 2e 75 74 69 6c 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73}
		$keyword4 = { 45 6d 70 74 79 53 65 74}
		$keyword5 = { 63 6f 6d 2e 73 75 6e 2e 6f 72 67 2e 61 70 61 63 68 65 2e 78 61 6c 61 6e 2e 69 6e 74 65 72 6e 61 6c 2e 78 73 6c 74 63 2e 74 72 61 78 2e 54 65 6d 70 6c 61 74 65 73 49 6d 70 6c}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
