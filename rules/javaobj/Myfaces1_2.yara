rule M_Methodology_HTTP_SerializedObject_JavaObj_Myfaces1_2_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: myfaces1_2javautilhashmaporgapachemyfacesviewfaceletselvalueexpressionmethodexpressionjavaxelmethodexpressionjavaxelexpressionorgapacheelvalueexpressionimpl"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLkhhc2hNYX|phdmEudXRpbC5IYXNoTWFw|qYXZhLnV0aWwuSGFzaE1hc)/
		$keyword1 = /(b3JnLmFwYWNoZS5teWZhY2VzLnZpZXcuZmFjZWxldHMuZWwuVmFsdWVFeHByZXNzaW9uTWV0aG9kRXhwcmVzc2lvb|9yZy5hcGFjaGUubXlmYWNlcy52aWV3LmZhY2VsZXRzLmVsLlZhbHVlRXhwcmVzc2lvbk1ldGhvZEV4cHJlc3Npb2|vcmcuYXBhY2hlLm15ZmFjZXMudmlldy5mYWNlbGV0cy5lbC5WYWx1ZUV4cHJlc3Npb25NZXRob2RFeHByZXNzaW9u)/
		$keyword2 = /(amF2YXguZWwuTWV0aG9kRXhwcmVzc2lvb|phdmF4LmVsLk1ldGhvZEV4cHJlc3Npb2|qYXZheC5lbC5NZXRob2RFeHByZXNzaW9u)/
		$keyword3 = /(amF2YXguZWwuRXhwcmVzc2lvb|phdmF4LmVsLkV4cHJlc3Npb2|qYXZheC5lbC5FeHByZXNzaW9u)/
		$keyword4 = /(b3JnLmFwYWNoZS5lbC5WYWx1ZUV4cHJlc3Npb25JbXBs|9yZy5hcGFjaGUuZWwuVmFsdWVFeHByZXNzaW9uSW1wb|vcmcuYXBhY2hlLmVsLlZhbHVlRXhwcmVzc2lvbkltcG)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Myfaces1_2_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: myfaces1_2javautilhashmaporgapachemyfacesviewfaceletselvalueexpressionmethodexpressionjavaxelmethodexpressionjavaxelexpressionorgapacheelvalueexpressionimpl"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 4d 61 70}
		$keyword1 = { 6f 72 67 2e 61 70 61 63 68 65 2e 6d 79 66 61 63 65 73 2e 76 69 65 77 2e 66 61 63 65 6c 65 74 73 2e 65 6c 2e 56 61 6c 75 65 45 78 70 72 65 73 73 69 6f 6e 4d 65 74 68 6f 64 45 78 70 72 65 73 73 69 6f 6e}
		$keyword2 = { 6a 61 76 61 78 2e 65 6c 2e 4d 65 74 68 6f 64 45 78 70 72 65 73 73 69 6f 6e}
		$keyword3 = { 6a 61 76 61 78 2e 65 6c 2e 45 78 70 72 65 73 73 69 6f 6e}
		$keyword4 = { 6f 72 67 2e 61 70 61 63 68 65 2e 65 6c 2e 56 61 6c 75 65 45 78 70 72 65 73 73 69 6f 6e 49 6d 70 6c}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
