rule M_Methodology_HTTP_SerializedObject_JavaObj_JBossInterceptors1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jbossinterceptors1orgjbossinterceptorproxyinterceptormethodhandlerorgjbossinterceptorbuilderinterceptionmodelimpllinkedhashsethashsetorgjbossinterceptorreadersimpleinterceptormetadata"
	strings:
		$objheader="rO"
		$keyword0 = /(b3JnLmpib3NzLmludGVyY2VwdG9yLnByb3h5LkludGVyY2VwdG9yTWV0aG9kSGFuZGxlc|9yZy5qYm9zcy5pbnRlcmNlcHRvci5wcm94eS5JbnRlcmNlcHRvck1ldGhvZEhhbmRsZX|vcmcuamJvc3MuaW50ZXJjZXB0b3IucHJveHkuSW50ZXJjZXB0b3JNZXRob2RIYW5kbGVy)/
		$keyword1 = /(b3JnLmpib3NzLmludGVyY2VwdG9yLmJ1aWxkZXIuSW50ZXJjZXB0aW9uTW9kZWxJbXBs|9yZy5qYm9zcy5pbnRlcmNlcHRvci5idWlsZGVyLkludGVyY2VwdGlvbk1vZGVsSW1wb|vcmcuamJvc3MuaW50ZXJjZXB0b3IuYnVpbGRlci5JbnRlcmNlcHRpb25Nb2RlbEltcG)/
		$keyword2 = /(TGlua2VkSGFzaFNld|xpbmtlZEhhc2hTZX|MaW5rZWRIYXNoU2V0)/
		$keyword3 = /(SGFzaFNld|hhc2hTZX|IYXNoU2V0)/
		$keyword4 = /(b3JnLmpib3NzLmludGVyY2VwdG9yLnJlYWRlci5TaW1wbGVJbnRlcmNlcHRvck1ldGFkYXRh|9yZy5qYm9zcy5pbnRlcmNlcHRvci5yZWFkZXIuU2ltcGxlSW50ZXJjZXB0b3JNZXRhZGF0Y|vcmcuamJvc3MuaW50ZXJjZXB0b3IucmVhZGVyLlNpbXBsZUludGVyY2VwdG9yTWV0YWRhdG)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_JBossInterceptors1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: jbossinterceptors1orgjbossinterceptorproxyinterceptormethodhandlerorgjbossinterceptorbuilderinterceptionmodelimpllinkedhashsethashsetorgjbossinterceptorreadersimpleinterceptormetadata"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6f 72 67 2e 6a 62 6f 73 73 2e 69 6e 74 65 72 63 65 70 74 6f 72 2e 70 72 6f 78 79 2e 49 6e 74 65 72 63 65 70 74 6f 72 4d 65 74 68 6f 64 48 61 6e 64 6c 65 72}
		$keyword1 = { 6f 72 67 2e 6a 62 6f 73 73 2e 69 6e 74 65 72 63 65 70 74 6f 72 2e 62 75 69 6c 64 65 72 2e 49 6e 74 65 72 63 65 70 74 69 6f 6e 4d 6f 64 65 6c 49 6d 70 6c}
		$keyword2 = { 4c 69 6e 6b 65 64 48 61 73 68 53 65 74}
		$keyword3 = { 48 61 73 68 53 65 74}
		$keyword4 = { 6f 72 67 2e 6a 62 6f 73 73 2e 69 6e 74 65 72 63 65 70 74 6f 72 2e 72 65 61 64 65 72 2e 53 69 6d 70 6c 65 49 6e 74 65 72 63 65 70 74 6f 72 4d 65 74 61 64 61 74 61}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1]) and (@keyword2[1] > @keyword1[1]) and (@keyword3[1] > @keyword2[1]) and (@keyword4[1] > @keyword3[1])
}
