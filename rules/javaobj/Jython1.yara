rule M_Methodology_HTTP_SerializedObject_JavaObj_Jython1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jython1javautilpriorityqueuejavautilcomparatorjavalangreflectproxyorgpythoncorepyfunctionorgpythoncorepyobject"
	strings:
		$objheader="rO"
		$keyword0 = /(amF2YS51dGlsLlByaW9yaXR5UXVldW|phdmEudXRpbC5Qcmlvcml0eVF1ZXVl|qYXZhLnV0aWwuUHJpb3JpdHlRdWV1Z)/
		$keyword1 = /(amF2YS51dGlsLkNvbXBhcmF0b3|phdmEudXRpbC5Db21wYXJhdG9y|qYXZhLnV0aWwuQ29tcGFyYXRvc)/
		$keyword2 = /(amF2YS5sYW5nLnJlZmxlY3QuUHJveH|phdmEubGFuZy5yZWZsZWN0LlByb3h5|qYXZhLmxhbmcucmVmbGVjdC5Qcm94e)/
		$keyword3 = /(b3JnLnB5dGhvbi5jb3JlLlB5RnVuY3Rpb2|9yZy5weXRob24uY29yZS5QeUZ1bmN0aW9u|vcmcucHl0aG9uLmNvcmUuUHlGdW5jdGlvb)/
		$keyword4 = /(b3JnLnB5dGhvbi5jb3JlLlB5T2JqZWN0|9yZy5weXRob24uY29yZS5QeU9iamVjd|vcmcucHl0aG9uLmNvcmUuUHlPYmplY3)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Jython1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jython1javautilpriorityqueuejavautilcomparatorjavalangreflectproxyorgpythoncorepyfunctionorgpythoncorepyobject"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6a 61 76 61 2e 75 74 69 6c 2e 50 72 69 6f 72 69 74 79 51 75 65 75 65}
		$keyword1 = { 6a 61 76 61 2e 75 74 69 6c 2e 43 6f 6d 70 61 72 61 74 6f 72}
		$keyword2 = { 6a 61 76 61 2e 6c 61 6e 67 2e 72 65 66 6c 65 63 74 2e 50 72 6f 78 79}
		$keyword3 = { 6f 72 67 2e 70 79 74 68 6f 6e 2e 63 6f 72 65 2e 50 79 46 75 6e 63 74 69 6f 6e}
		$keyword4 = { 6f 72 67 2e 70 79 74 68 6f 6e 2e 63 6f 72 65 2e 50 79 4f 62 6a 65 63 74}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
