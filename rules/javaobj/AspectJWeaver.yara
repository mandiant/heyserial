rule M_Methodology_HTTP_SerializedObject_JavaObj_AspectJWeaver_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: aspectjweaverhashsettiedmapentryorgapachecommonscollectionsfunctorsconstanttransformerorgaspectjweavertoolscachesimplecachestoreablecachingmap"
	strings:
		$objheader="rO"
		$keyword0 = /(SGFzaFNld|hhc2hTZX|IYXNoU2V0)/
		$keyword1 = /(VGllZE1hcEVudHJ5|RpZWRNYXBFbnRye|UaWVkTWFwRW50cn)/
		$keyword2 = /(b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3Jz|9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9yc|vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3Rvcn)/
		$keyword3 = /(Q29uc3RhbnRUcmFuc2Zvcm1lc|NvbnN0YW50VHJhbnNmb3JtZX|Db25zdGFudFRyYW5zZm9ybWVy)/
		$keyword4 = /(b3JnLmFzcGVjdGoud2VhdmVyLnRvb2xzLmNhY2hlLlNpbXBsZUNhY2hl|9yZy5hc3BlY3RqLndlYXZlci50b29scy5jYWNoZS5TaW1wbGVDYWNoZ|vcmcuYXNwZWN0ai53ZWF2ZXIudG9vbHMuY2FjaGUuU2ltcGxlQ2FjaG)/
		$keyword5 = /(U3RvcmVhYmxlQ2FjaGluZ01hc|N0b3JlYWJsZUNhY2hpbmdNYX|TdG9yZWFibGVDYWNoaW5nTWFw)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_AspectJWeaver_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: aspectjweaverhashsettiedmapentryorgapachecommonscollectionsfunctorsconstanttransformerorgaspectjweavertoolscachesimplecachestoreablecachingmap"
	strings:
		$objheader={ac ed}
		$keyword0 = { 48 61 73 68 53 65 74}
		$keyword1 = { 54 69 65 64 4d 61 70 45 6e 74 72 79}
		$keyword2 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 66 75 6e 63 74 6f 72 73}
		$keyword3 = { 43 6f 6e 73 74 61 6e 74 54 72 61 6e 73 66 6f 72 6d 65 72}
		$keyword4 = { 6f 72 67 2e 61 73 70 65 63 74 6a 2e 77 65 61 76 65 72 2e 74 6f 6f 6c 73 2e 63 61 63 68 65 2e 53 69 6d 70 6c 65 43 61 63 68 65}
		$keyword5 = { 53 74 6f 72 65 61 62 6c 65 43 61 63 68 69 6e 67 4d 61 70}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
