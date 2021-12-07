rule M_Methodology_HTTP_SerializedObject_JavaObj_MozillaRhino2_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: mozillarhino2orgmozillajavascriptnativejavaobjectorgmozillajavascripttoolsshellenvironmentorgmozillajavascriptscriptableobjectjavautilhashtableorgmozillajavascriptclasscache"
	strings:
		$objheader="rO"
		$keyword0 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC5OYXRpdmVKYXZhT2JqZWN0|9yZy5tb3ppbGxhLmphdmFzY3JpcHQuTmF0aXZlSmF2YU9iamVjd|vcmcubW96aWxsYS5qYXZhc2NyaXB0Lk5hdGl2ZUphdmFPYmplY3)/
		$keyword1 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC50b29scy5zaGVsbC5FbnZpcm9ubWVud|9yZy5tb3ppbGxhLmphdmFzY3JpcHQudG9vbHMuc2hlbGwuRW52aXJvbm1lbn|vcmcubW96aWxsYS5qYXZhc2NyaXB0LnRvb2xzLnNoZWxsLkVudmlyb25tZW50)/
		$keyword2 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC5TY3JpcHRhYmxlT2JqZWN0|9yZy5tb3ppbGxhLmphdmFzY3JpcHQuU2NyaXB0YWJsZU9iamVjd|vcmcubW96aWxsYS5qYXZhc2NyaXB0LlNjcmlwdGFibGVPYmplY3)/
		$keyword3 = /(amF2YS51dGlsLkhhc2h0YWJsZ|phdmEudXRpbC5IYXNodGFibG|qYXZhLnV0aWwuSGFzaHRhYmxl)/
		$keyword4 = /(b3JnLm1vemlsbGEuamF2YXNjcmlwdC5DbGFzc0NhY2hl|9yZy5tb3ppbGxhLmphdmFzY3JpcHQuQ2xhc3NDYWNoZ|vcmcubW96aWxsYS5qYXZhc2NyaXB0LkNsYXNzQ2FjaG)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_MozillaRhino2_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: mozillarhino2orgmozillajavascriptnativejavaobjectorgmozillajavascripttoolsshellenvironmentorgmozillajavascriptscriptableobjectjavautilhashtableorgmozillajavascriptclasscache"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 4e 61 74 69 76 65 4a 61 76 61 4f 62 6a 65 63 74}
		$keyword1 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 74 6f 6f 6c 73 2e 73 68 65 6c 6c 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74}
		$keyword2 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 53 63 72 69 70 74 61 62 6c 65 4f 62 6a 65 63 74}
		$keyword3 = { 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73 68 74 61 62 6c 65}
		$keyword4 = { 6f 72 67 2e 6d 6f 7a 69 6c 6c 61 2e 6a 61 76 61 73 63 72 69 70 74 2e 43 6c 61 73 73 43 61 63 68 65}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
