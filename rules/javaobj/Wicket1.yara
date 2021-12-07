rule M_Methodology_HTTP_SerializedObject_JavaObj_Wicket1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: wicket1orgapachewicketutiluploaddiskfileitemjavaiofile"
	strings:
		$objheader="rO"
		$keyword0 = /(b3JnLmFwYWNoZS53aWNrZXQudXRpbC51cGxvYWQuRGlza0ZpbGVJdGVt|9yZy5hcGFjaGUud2lja2V0LnV0aWwudXBsb2FkLkRpc2tGaWxlSXRlb|vcmcuYXBhY2hlLndpY2tldC51dGlsLnVwbG9hZC5EaXNrRmlsZUl0ZW)/
		$keyword1 = /(amF2YS5pby5GaWxl|phdmEuaW8uRmlsZ|qYXZhLmlvLkZpbG)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Wicket1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: wicket1orgapachewicketutiluploaddiskfileitemjavaiofile"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6f 72 67 2e 61 70 61 63 68 65 2e 77 69 63 6b 65 74 2e 75 74 69 6c 2e 75 70 6c 6f 61 64 2e 44 69 73 6b 46 69 6c 65 49 74 65 6d}
		$keyword1 = { 6a 61 76 61 2e 69 6f 2e 46 69 6c 65}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1])
}
