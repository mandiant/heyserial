rule M_Methodology_HTTP_SerializedObject_JavaObj_Hibernate1_2_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: hibernate1_2javautilhashmaporghibernateenginespitypedvalueorghibernatetypecomponenttypeabstracttypeorghibernatetuplecomponentpojocomponenttuplizer"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLkhhc2hNYX|phdmEudXRpbC5IYXNoTWFw|qYXZhLnV0aWwuSGFzaE1hc)/
		$keyword1 = /(b3JnLmhpYmVybmF0ZS5lbmdpbmUuc3BpLlR5cGVkVmFsdW|9yZy5oaWJlcm5hdGUuZW5naW5lLnNwaS5UeXBlZFZhbHVl|vcmcuaGliZXJuYXRlLmVuZ2luZS5zcGkuVHlwZWRWYWx1Z)/
		$keyword2 = /(b3JnLmhpYmVybmF0ZS50eXBl|9yZy5oaWJlcm5hdGUudHlwZ|vcmcuaGliZXJuYXRlLnR5cG)/
		$keyword3 = /(Q29tcG9uZW50VHlwZ|NvbXBvbmVudFR5cG|Db21wb25lbnRUeXBl)/
		$keyword4 = /(QWJzdHJhY3RUeXBl|Fic3RyYWN0VHlwZ|BYnN0cmFjdFR5cG)/
		$keyword5 = /(b3JnLmhpYmVybmF0ZS50dXBsZS5jb21wb25lbnQuUG9qb0NvbXBvbmVudFR1cGxpemVy|9yZy5oaWJlcm5hdGUudHVwbGUuY29tcG9uZW50LlBvam9Db21wb25lbnRUdXBsaXplc|vcmcuaGliZXJuYXRlLnR1cGxlLmNvbXBvbmVudC5Qb2pvQ29tcG9uZW50VHVwbGl6ZX)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Hibernate1_2_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: hibernate1_2javautilhashmaporghibernateenginespitypedvalueorghibernatetypecomponenttypeabstracttypeorghibernatetuplecomponentpojocomponenttuplizer"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 4d 61 70}
		$keyword1 = { 6f 72 67 2e 68 69 62 65 72 6e 61 74 65 2e 65 6e 67 69 6e 65 2e 73 70 69 2e 54 79 70 65 64 56 61 6c 75 65}
		$keyword2 = { 6f 72 67 2e 68 69 62 65 72 6e 61 74 65 2e 74 79 70 65}
		$keyword3 = { 43 6f 6d 70 6f 6e 65 6e 74 54 79 70 65}
		$keyword4 = { 41 62 73 74 72 61 63 74 54 79 70 65}
		$keyword5 = { 6f 72 67 2e 68 69 62 65 72 6e 61 74 65 2e 74 75 70 6c 65 2e 63 6f 6d 70 6f 6e 65 6e 74 2e 50 6f 6a 6f 43 6f 6d 70 6f 6e 65 6e 74 54 75 70 6c 69 7a 65 72}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
