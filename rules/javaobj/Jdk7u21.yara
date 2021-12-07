rule M_Methodology_HTTP_SerializedObject_JavaObj_Jdk7u21_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jdk7u21javautillinkedhashsethashsetcomsunorgapachexalaninternalxsltctraxtemplatesimpljavaxxmltransformtemplatesjavalangreflectproxy"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLkxpbmtlZEhhc2hTZX|phdmEudXRpbC5MaW5rZWRIYXNoU2V0|qYXZhLnV0aWwuTGlua2VkSGFzaFNld)/
		$keyword1 = /(SGFzaFNld|hhc2hTZX|IYXNoU2V0)/
		$keyword2 = /(Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wb|NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcG|jb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBs)/
		$keyword3 = /(amF2YXgueG1sLnRyYW5zZm9ybS5UZW1wbGF0ZX|phdmF4LnhtbC50cmFuc2Zvcm0uVGVtcGxhdGVz|qYXZheC54bWwudHJhbnNmb3JtLlRlbXBsYXRlc)/
		$keyword4 = /(amF2YS5sYW5nLnJlZmxlY3QuUHJveH|phdmEubGFuZy5yZWZsZWN0LlByb3h5|qYXZhLmxhbmcucmVmbGVjdC5Qcm94e)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Jdk7u21_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jdk7u21javautillinkedhashsethashsetcomsunorgapachexalaninternalxsltctraxtemplatesimpljavaxxmltransformtemplatesjavalangreflectproxy"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 4c 69 6e 6b 65 64 48 61 73 68 53 65 74}
		$keyword1 = { 48 61 73 68 53 65 74}
		$keyword2 = { 63 6f 6d 2e 73 75 6e 2e 6f 72 67 2e 61 70 61 63 68 65 2e 78 61 6c 61 6e 2e 69 6e 74 65 72 6e 61 6c 2e 78 73 6c 74 63 2e 74 72 61 78 2e 54 65 6d 70 6c 61 74 65 73 49 6d 70 6c}
		$keyword3 = { 6a 61 76 61 78 2e 78 6d 6c 2e 74 72 61 6e 73 66 6f 72 6d 2e 54 65 6d 70 6c 61 74 65 73}
		$keyword4 = { 6a 61 76 61 2e 6c 61 6e 67 2e 72 65 66 6c 65 63 74 2e 50 72 6f 78 79}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
