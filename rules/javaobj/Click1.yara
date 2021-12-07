rule M_Methodology_HTTP_SerializedObject_JavaObj_Click1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: click1javautilpriorityqueueorgapacheclickcontrolcolumncolumntableabstractcontrol"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLlByaW9yaXR5UXVldW|phdmEudXRpbC5Qcmlvcml0eVF1ZXVl|qYXZhLnV0aWwuUHJpb3JpdHlRdWV1Z)/
		$keyword1 = /(b3JnLmFwYWNoZS5jbGljay5jb250cm9sLkNvbHVtb|9yZy5hcGFjaGUuY2xpY2suY29udHJvbC5Db2x1bW|vcmcuYXBhY2hlLmNsaWNrLmNvbnRyb2wuQ29sdW1u)/
		$keyword2 = /(Q29sdW1u|NvbHVtb|Db2x1bW)/
		$keyword3 = /(VGFibG|RhYmxl|UYWJsZ)/
		$keyword4 = /(QWJzdHJhY3RDb250cm9s|Fic3RyYWN0Q29udHJvb|BYnN0cmFjdENvbnRyb2)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Click1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: click1javautilpriorityqueueorgapacheclickcontrolcolumncolumntableabstractcontrol"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 50 72 69 6f 72 69 74 79 51 75 65 75 65}
		$keyword1 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6c 69 63 6b 2e 63 6f 6e 74 72 6f 6c 2e 43 6f 6c 75 6d 6e}
		$keyword2 = { 43 6f 6c 75 6d 6e}
		$keyword3 = { 54 61 62 6c 65}
		$keyword4 = { 41 62 73 74 72 61 63 74 43 6f 6e 74 72 6f 6c}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
