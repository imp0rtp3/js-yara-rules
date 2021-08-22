rule meow_js_miner
{

    meta:
       author = "Brian Laskowski"
       info = " meow.js cryptominer 05/17/18 "
       license = "GNU GPLv3"
       license_reference = "https://choosealicense.com/licenses/gpl-3.0/"

    strings:
    
   	$s1="data"
	$s7="application/octet-stream"
	$s8="base64"
	$s2="hashsolved"  
	$s3="k.identifier" 
	$s4="acceptedhashes"
	$s5="eth-pocket"
	$s6="8585"

    condition:
    7 of them
}

