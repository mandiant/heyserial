rule M_Methodology_HTTP_SerializedObject_JavaObj_MozillaRhino1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: mozillarhino1orgmozillajavascriptnativeerrororgmozillajavascriptnativejavaobjectorgmozillajavascriptmemberbox"
	strings:
		$objheader="rO"
		$keyword0 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC5OYXRpdmVFcnJvc|9yZy5tb3ppbGxhLmphdmFzY3JpcHQuTmF0aXZlRXJyb3|vcmcubW96aWxsYS5qYXZhc2NyaXB0Lk5hdGl2ZUVycm9y)/
		$keyword1 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC5OYXRpdmVKYXZhT2JqZWN0|9yZy5tb3ppbGxhLmphdmFzY3JpcHQuTmF0aXZlSmF2YU9iamVjd|vcmcubW96aWxsYS5qYXZhc2NyaXB0Lk5hdGl2ZUphdmFPYmplY3)/
		$keyword2 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC5NZW1iZXJCb3|9yZy5tb3ppbGxhLmphdmFzY3JpcHQuTWVtYmVyQm94|vcmcubW96aWxsYS5qYXZhc2NyaXB0Lk1lbWJlckJve)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_MozillaRhino1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: mozillarhino1orgmozillajavascriptnativeerrororgmozillajavascriptnativejavaobjectorgmozillajavascriptmemberbox"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 4e 61 74 69 76 65 45 72 72 6f 72}
		$keyword1 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 4e 61 74 69 76 65 4a 61 76 61 4f 62 6a 65 63 74}
		$keyword2 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 4d 65 6d 62 65 72 42 6f 78}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1])
}
