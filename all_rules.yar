rule SocGholish_JS_Inject_1
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
		all of them		
}

rule SocGholish_JS_Inject_2
{
	meta:
		author = "Josh Trombley "
		date_created = "9/2/2021"

	strings:
		$s0 = "new RegExp"
		$s1 = "document.createElement('script')"
		$s2 = "type = 'text/javascript'"
		$s3 = "document.getElementsByTagName('script')"
		$s4 = "parentNode.insertBefore"
        	$s5 = "window.atob"

	condition:
		all of them		
}
