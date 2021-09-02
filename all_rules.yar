rule SocGholish_JS_Inject
{
	meta:
		author = "Josh Trombley "
		date_created = "9/2/2021"

	strings:
		$s0 = "cmVmZXJyZXI="
		$s1 = "Oi8vKFteL10rKS8="
		$s2 = "dXNlckFnZW50"
		$s3 = "bG9jYWxTdG9yYWdl"
		$s4 = "V2luZG93cw=="

	condition:
		4 of them		
}
