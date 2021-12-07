rule M_Methodology_HTTP_SerializedObject_JavaObj_URLDNS_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: urldnsjavautilhashmapjavaneturl"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLkhhc2hNYX|phdmEudXRpbC5IYXNoTWFw|qYXZhLnV0aWwuSGFzaE1hc)/
		$keyword1 = /(amF2YS5uZXQuVVJM|phdmEubmV0LlVST|qYXZhLm5ldC5VUk)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_URLDNS_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: urldnsjavautilhashmapjavaneturl"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 4d 61 70}
		$keyword1 = { 6a 61 76 61 2e 6e 65 74 2e 55 52 4c}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1])
}
