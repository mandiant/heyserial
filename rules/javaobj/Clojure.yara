rule M_Methodology_HTTP_SerializedObject_JavaObj_Clojure_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: clojurehashmapclojureinspectorproxyjavaxswingtableabstracttablemodelff19274eventlistenerlistclojurelangpersistentarraymap"
	strings:
		$objheader="rO"
		$keyword0 = /(SGFzaE1hc|hhc2hNYX|IYXNoTWFw)/
		$keyword1 = /(Y2xvanVyZS5pbnNwZWN0b3IucHJveH|Nsb2p1cmUuaW5zcGVjdG9yLnByb3h5|jbG9qdXJlLmluc3BlY3Rvci5wcm94e)/
		$keyword2 = /(amF2YXguc3dpbmcudGFibGUuQWJzdHJhY3RUYWJsZU1vZGVs|phdmF4LnN3aW5nLnRhYmxlLkFic3RyYWN0VGFibGVNb2Rlb|qYXZheC5zd2luZy50YWJsZS5BYnN0cmFjdFRhYmxlTW9kZW)/
		$keyword3 = /(ZmYxOTI3N|ZmMTkyNz|mZjE5Mjc0)/
		$keyword4 = /(RXZlbnRMaXN0ZW5lckxpc3|V2ZW50TGlzdGVuZXJMaXN0|FdmVudExpc3RlbmVyTGlzd)/
		$keyword5 = /(Y2xvanVyZS5sYW5nLlBlcnNpc3RlbnRBcnJheU1hc|Nsb2p1cmUubGFuZy5QZXJzaXN0ZW50QXJyYXlNYX|jbG9qdXJlLmxhbmcuUGVyc2lzdGVudEFycmF5TWFw)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_Clojure_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: clojurehashmapclojureinspectorproxyjavaxswingtableabstracttablemodelff19274eventlistenerlistclojurelangpersistentarraymap"
	strings:
		$objheader={ac ed}
		$keyword0 = { 48 61 73 68 4d 61 70}
		$keyword1 = { 63 6c 6f 6a 75 72 65 2e 69 6e 73 70 65 63 74 6f 72 2e 70 72 6f 78 79}
		$keyword2 = { 6a 61 76 61 78 2e 73 77 69 6e 67 2e 74 61 62 6c 65 2e 41 62 73 74 72 61 63 74 54 61 62 6c 65 4d 6f 64 65 6c}
		$keyword3 = { 66 66 31 39 32 37 34}
		$keyword4 = { 45 76 65 6e 74 4c 69 73 74 65 6e 65 72 4c 69 73 74}
		$keyword5 = { 63 6c 6f 6a 75 72 65 2e 6c 61 6e 67 2e 50 65 72 73 69 73 74 65 6e 74 41 72 72 61 79 4d 61 70}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1]) and (@keyword5[1] > @keyword4[1])
}
