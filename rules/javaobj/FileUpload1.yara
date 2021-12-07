rule M_Methodology_HTTP_SerializedObject_JavaObj_FileUpload1_base64 {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: fileupload1orgapachecommonsfileuploaddiskdiskfileitemjavaiofile"
	strings:
		$objheader="rO"
		$keyword0 = /(b3JnLmFwYWNoZS5jb21tb25zLmZpbGV1cGxvYWQuZGlzay5EaXNrRmlsZUl0ZW|9yZy5hcGFjaGUuY29tbW9ucy5maWxldXBsb2FkLmRpc2suRGlza0ZpbGVJdGVt|vcmcuYXBhY2hlLmNvbW1vbnMuZmlsZXVwbG9hZC5kaXNrLkRpc2tGaWxlSXRlb)/
		$keyword1 = /(amF2YS5pby5GaWxl|phdmEuaW8uRmlsZ|qYXZhLmlvLkZpbG)/
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1])
}
rule M_Methodology_HTTP_SerializedObject_JavaObj_FileUpload1_raw {
	meta:
		author="Alyssa Rahman @ramen0x3f - heyserial.py"
		description="Auto-generated rule for serialized objects with the keyword/chain: fileupload1orgapachecommonsfileuploaddiskdiskfileitemjavaiofile"
	strings:
		$objheader={ac ed}
		$keyword0 = { 6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 66 69 6c 65 75 70 6c 6f 61 64 2e 64 69 73 6b 2e 44 69 73 6b 46 69 6c 65 49 74 65 6d}
		$keyword1 = { 6a 61 76 61 2e 69 6f 2e 46 69 6c 65}
	condition:
		$objheader and (@keyword0[1] > @objheader[1]) and (@keyword1[1] > @keyword0[1])
}
