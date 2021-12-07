rule M_Methodology_HTTP_SerializedObject_JavaObj_Vaadin1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: vaadin1javaxmanagementbadattributevalueexpexceptioncomvaadindatautilpropertysetitemcomvaadindatautilnestedmethodpropertycomsunorgapachexalaninternalxsltctraxtemplatesimpl"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YXgubWFuYWdlbWVudC5CYWRBdHRyaWJ1dGVWYWx1ZUV4cEV4Y2VwdGlvb|phdmF4Lm1hbmFnZW1lbnQuQmFkQXR0cmlidXRlVmFsdWVFeHBFeGNlcHRpb2|qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u)/
		$keyword1 = /(Y29tLnZhYWRpbi5kYXRhLnV0aWwuUHJvcGVydHlzZXRJdGVt|NvbS52YWFkaW4uZGF0YS51dGlsLlByb3BlcnR5c2V0SXRlb|jb20udmFhZGluLmRhdGEudXRpbC5Qcm9wZXJ0eXNldEl0ZW)/
		$keyword2 = /(Y29tLnZhYWRpbi5kYXRhLnV0aWwuTmVzdGVkTWV0aG9kUHJvcGVydH|NvbS52YWFkaW4uZGF0YS51dGlsLk5lc3RlZE1ldGhvZFByb3BlcnR5|jb20udmFhZGluLmRhdGEudXRpbC5OZXN0ZWRNZXRob2RQcm9wZXJ0e)/
		$keyword3 = /(Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wb|NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcG|jb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBs)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Vaadin1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: vaadin1javaxmanagementbadattributevalueexpexceptioncomvaadindatautilpropertysetitemcomvaadindatautilnestedmethodpropertycomsunorgapachexalaninternalxsltctraxtemplatesimpl"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 78 2e 6d 61 6e 61 67 65 6d 65 6e 74 2e 42 61 64 41 74 74 72 69 62 75 74 65 56 61 6c 75 65 45 78 70 45 78 63 65 70 74 69 6f 6e}
		$keyword1 = { 63 6f 6d 2e 76 61 61 64 69 6e 2e 64 61 74 61 2e 75 74 69 6c 2e 50 72 6f 70 65 72 74 79 73 65 74 49 74 65 6d}
		$keyword2 = { 63 6f 6d 2e 76 61 61 64 69 6e 2e 64 61 74 61 2e 75 74 69 6c 2e 4e 65 73 74 65 64 4d 65 74 68 6f 64 50 72 6f 70 65 72 74 79}
		$keyword3 = { 63 6f 6d 2e 73 75 6e 2e 6f 72 67 2e 61 70 61 63 68 65 2e 78 61 6c 61 6e 2e 69 6e 74 65 72 6e 61 6c 2e 78 73 6c 74 63 2e 74 72 61 78 2e 54 65 6d 70 6c 61 74 65 73 49 6d 70 6c}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1])
}
