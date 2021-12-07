rule M_Methodology_HTTP_SerializedObject_JavaObj_JRMPListener_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jrmplistenersunrmiserveractivationgroupimpljavarmiactivationactivationgroupjavarmiserverunicastremoteobjectjavarmiserverremoteserverjavarmiserverremoteobject"
	strings:
		$objheader="rO"
		$keyword0 = /(c3VuLnJtaS5zZXJ2ZXIuQWN0aXZhdGlvbkdyb3VwSW1wb|N1bi5ybWkuc2VydmVyLkFjdGl2YXRpb25Hcm91cEltcG|zdW4ucm1pLnNlcnZlci5BY3RpdmF0aW9uR3JvdXBJbXBs)/
		$keyword1 = /(amF2YS5ybWkuYWN0aXZhdGlvbi5BY3RpdmF0aW9uR3JvdX|phdmEucm1pLmFjdGl2YXRpb24uQWN0aXZhdGlvbkdyb3Vw|qYXZhLnJtaS5hY3RpdmF0aW9uLkFjdGl2YXRpb25Hcm91c)/
		$keyword2 = /(amF2YS5ybWkuc2VydmVyLlVuaWNhc3RSZW1vdGVPYmplY3|phdmEucm1pLnNlcnZlci5VbmljYXN0UmVtb3RlT2JqZWN0|qYXZhLnJtaS5zZXJ2ZXIuVW5pY2FzdFJlbW90ZU9iamVjd)/
		$keyword3 = /(amF2YS5ybWkuc2VydmVyLlJlbW90ZVNlcnZlc|phdmEucm1pLnNlcnZlci5SZW1vdGVTZXJ2ZX|qYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlU2VydmVy)/
		$keyword4 = /(amF2YS5ybWkuc2VydmVyLlJlbW90ZU9iamVjd|phdmEucm1pLnNlcnZlci5SZW1vdGVPYmplY3|qYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN0)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_JRMPListener_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jrmplistenersunrmiserveractivationgroupimpljavarmiactivationactivationgroupjavarmiserverunicastremoteobjectjavarmiserverremoteserverjavarmiserverremoteobject"
	strings:
		$objheader={ac ed}
		$keyword0 = { 73 75 6e 2e 72 6d 69 2e 73 65 72 76 65 72 2e 41 63 74 69 76 61 74 69 6f 6e 47 72 6f 75 70 49 6d 70 6c}
		$keyword1 = { 6a 61 76 61 2e 72 6d 69 2e 61 63 74 69 76 61 74 69 6f 6e 2e 41 63 74 69 76 61 74 69 6f 6e 47 72 6f 75 70}
		$keyword2 = { 6a 61 76 61 2e 72 6d 69 2e 73 65 72 76 65 72 2e 55 6e 69 63 61 73 74 52 65 6d 6f 74 65 4f 62 6a 65 63 74}
		$keyword3 = { 6a 61 76 61 2e 72 6d 69 2e 73 65 72 76 65 72 2e 52 65 6d 6f 74 65 53 65 72 76 65 72}
		$keyword4 = { 6a 61 76 61 2e 72 6d 69 2e 73 65 72 76 65 72 2e 52 65 6d 6f 74 65 4f 62 6a 65 63 74}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
