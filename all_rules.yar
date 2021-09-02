
/* 
    YARA Rules by Florian
    Mostly based on MSTICs report 
    https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/
    Not shared publicly: rules for CobaltStrike loader samples, ISOs, specifc msiexec method found in some samples
    only available in THOR and VALHALLA
*/

rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_1 {
   meta:
      description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29"
   strings:
      $x1 = "[i].charCodeAt(0) ^ 2);}"
   condition:
      filesize < 5000KB and 1 of them
}

rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_2 {
   meta:
      description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29"
   strings:
      $s1 = "saveAs(blob, " ascii
      $s2 = ".iso\");" ascii
      $s3 = "application/x-cd-image" ascii
      $s4 = ".indexOf(\"Win\")!=-1" ascii
   condition:
      filesize < 5000KB and all of them
}


rule apt_CN_Tetris_JS_simple
{

	meta:
		author      = "@imp0rtp3"
		description = "Jetriz, Swid & Jeniva from Tetris framework signature"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		
	strings:
		$a1 = "c2lnbmFs" // 'noRefererJsonp'
		$a2 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a3 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a4 = "ZmV0Y2g=" // 'return new F('
		$a5 = "c3BsaWNl" // 'Mb2345Browser'
		$a6 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a7 = "Zm9udA==" // 'heartBeats'
		$a8 = "OS4w" // 'addIEMeta'
		$a9 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "UHJlc3Rv" // 'baiduboxapp'
		$a12 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a13 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a14 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a15 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'

		$b1 = "var a0_0x"

	condition:
		$b1 at 0 or
		5 of ($a*)

}


rule APT_EvilNum_JS_Jul_2021_1 {
   meta:
        description = "Detect JS script used by EvilNum group"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2020-07-13"
        hash1 = "8420577149bef1eb12387be3ea7c33f70272e457891dfe08fdb015ba7cd92c72"
        hash2 = "c16824a585c9a77332fc16357b5e00fc110c00535480e9495c627f656bb60f24"
        hash3 = "1061baf604aaa7ed5ba3026b9367de7b6c7f20e7e706d9e9b5308c45a64b2679"
        tlp = "white"
        adversary = "EvilNum"
   strings:
        $s1 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 42 61 73 65 36 34 44 61 74 61 22 29 3b }
        $s2 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 42 61 73 65 36 34 44 61 74 61 22 29 3b }
        $s3 = { 69 66 20 28 2d 31 20 21 3d 20 57 53 63 72 69 70 74 2e 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 2e 69 6e 64 65 78 4f 66 28 [1-8] 28 22 }
        $s4 = { 52 75 6e 28 [1-8] 30 2c 20 30 29 }
        $s5 = { 7d 2c 20 ?? 20 3d 20 ?? 2e 63 68 61 72 43 6f 64 65 41 74 28 30 29 2c 20 ?? 20 3d 20 ?? 2e 73 6c 69 63 65 28 31 2c 20 31 20 2b 20 ?? 29 2c 20 ?? 20 3d 20 ?? 2e 73 6c 69 63 65 28 31 20 2b 20 ?? 20 2b 20 34 29 2c 20 ?? 20 3d 20 5b 5d 2c } 
        $s6 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 3b }
        $s7 = { 5b ?? 5d 20 3d 20 ?? 20 2b 20 22 2d 22 20 2b 20 ?? 20 2b 20 22 2d 22 20 2b 20 ?? 20 2b 20 22 54 22 20 2b 20 ?? 20 2b 20 22 3a 22 20 2b 20 ?? 20 2b 20 22 3a 22 20 2b 20 ?? 3b }
   condition:
        filesize > 8KB and 6 of ($s*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-06-26
   Identifier: RANCOR
   Reference: https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_RANCOR_JS_Malware {
   meta:
      description = "Rancor Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "1dc5966572e94afc2fbcf8e93e3382eef4e4d7b5bc02f24069c403a28fa6a458"
   strings:
      $x1 = ",0,0 >%SystemRoot%\\system32\\spool\\drivers\\color\\fb.vbs\",0,0" fullword ascii
      $x2 = "CreateObject(\"Wscript.Shell\").Run \"explorer.exe \"\"http" ascii
      $x3 = "CreateObject(\"Wscript.Shell\").Run \"schtasks /create" ascii
   condition:
      uint16(0) == 0x533c and filesize < 1KB and 1 of them
}



rule MAL_Emotet_JS_Dropper_Oct19_1 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }
   condition:
      uint32(0) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}



rule MAL_ZIP_SocGholish_Mar21_1 : zip js socgholish {
    meta:
        description = "Triggers on small zip files with typical SocGholish JS files in it"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        hash = "4f6566c145be5046b6be6a43c64d0acae38cada5eb49b2f73135b3ac3d6ba770"
        hash = "54f756fbf8c20c76af7c9f538ff861690800c622d1c9db26eb3afedc50835b09"
        hash = "dfdbec1846b74238ba3cfb8c7580c64a0fa8b14b6ed2b0e0e951cc6a9202dd8d"
    strings:
        $a1 = /\.[a-z0-9]{6}\.js/ ascii
        $a2 = "Chrome" ascii
        $a3 = "Opera" ascii

        $b1 = "Firefox.js" ascii
        $b2 = "Edge.js" ascii
    condition:
        uint16(0) == 0x4b50 and filesize > 1300 and filesize < 1600 and (
            2 of ($a*) or
            any of ($b*)
        )
}

rule MAL_JS_SocGholish_Mar21_1 : js socgholish {
    meta:
        description = "Triggers on SocGholish JS files"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
        hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
        hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
    strings:
        $try = "try" ascii

        $s1 = "new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s2 = "['DeleteFile']" ascii
        $s3 = "['WScript']['ScriptFullName']" ascii
        $s4 = "['WScript']['Sleep'](1000)" ascii
        $s5 = "new ActiveXObject('MSXML2.XMLHTTP')" ascii
        $s6 = "this['eval']" ascii
        $s7 = "String['fromCharCode']"
        $s8 = "2), 16)," ascii
        $s9 = "= 103," ascii
        $s10 = "'00000000'" ascii
    condition:
        $try in (0 .. 10) and filesize > 3KB and filesize < 5KB and 8 of ($s*)
}

rule SocGholish_JS_Inject
{
	meta:
		author = "Josh Trombley "
		date_created = "9/2/2021"

	strings:
		$s0 = "cmVmZXJyZXI=" fullword
		$s1 = "Oi8vKFteL10rKS8=" fullword
		$s2 = "dXNlckFnZW50" fullword
		$s3 = "bG9jYWxTdG9yYWdl" fullword
		$s4 = "V2luZG93cw==" fullword

	condition:
		all of them		
}


/*
   YARA Rule Set
   Author: Florian Roth
   Date: 2018-09-18
   Identifier: Xbash
   License: https://creativecommons.org/licenses/by-nc/4.0/
   Reference: https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/
*/

/* Rule Set ----------------------------------------------------------------- */


rule MAL_Xbash_JS_Sep18 {
   meta:
      description = "Detects XBash malware"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18"
      hash1 = "f888dda9ca1876eba12ffb55a7a993bd1f5a622a30045a675da4955ede3e4cb8"
   strings:
      $s1 = "var path=WSHShell" fullword ascii
      $s2 = "var myObject= new ActiveXObject(" fullword ascii
      $s3 = "window.resizeTo(0,0)" fullword ascii
      $s4 = "<script language=\"JScript\">" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x483c and filesize < 5KB and
      8 of them
}

/*

   Generic Cloaking

   Florian Roth
   Nextron Systems GmbH

	License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/



rule Obfuscated_JS_April17 {
   meta:
      description = "Detects cloaked Mimikatz in JS obfuscation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21"
   strings:
      $s1 = "\";function Main(){for(var "  ascii
      $s2 = "=String.fromCharCode(parseInt(" ascii
      $s3 = "));(new Function(" ascii
   condition:
      filesize < 500KB and all of them
}


rule Malware_JS_powershell_obfuscated {
   meta:
      description = "Unspecified malware - file rechnung_3.js"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-24"
      hash1 = "3af15a2d60f946e0c4338c84bd39880652f676dc884057a96a10d7f802215760"
   strings:
      $x1 = "po\" + \"wer\" + \"sh\" + \"e\" + \"ll\";" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}


/* Various rules - see the references */

rule JS_Suspicious_Obfuscation_Dropbox {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
      $x2 = "script:https://www.dropbox.com" ascii
   condition:
      2 of them
}

rule JS_Suspicious_MSHTA_Bypass {
   meta:
      description = "Detects MSHTA Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition:
      2 of them
}

rule JavaScript_Run_Suspicious {
   meta:
      description = "Detects a suspicious Javascript Run command"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      score = 60
      date = "2017-08-23"
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition:
      all of them
}


rule Suspicious_JS_script_content {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Research on Leviathan https://goo.gl/MZ7dRg"
      date = "2017-12-02"
      score = 70
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition:
      ( filesize < 10KB and 1 of them )
}

rule Universal_Exploit_Strings {
   meta:
      description = "Detects a group of strings often used in exploit codes"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "not set"
      date = "2017-12-02"
      score = 50
      hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"
   strings:
      $s1 = "Exploit" fullword ascii
      $s2 = "Payload" fullword ascii
      $s3 = "CVE-201" ascii
      $s4 = "bindshell"
   condition:
      ( filesize < 2KB and 3 of them )
}



rule Loa_JS_Gootkit_Nov_2020_1 {
   meta:
      description = "Detect JS loader used on the Gootkit killchain (November 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ffforward/status/1330214661577437187"
      date = "2020-11-21"
      hash1 = "7aec3ed791529182c0f64ce34415c3c705a79f3d628cbcff70c34a9f73d8ff42"
   strings:
      $s1 = { 7b [4-6] 5b [4-6] 5d 28 [4-6] 5b [4-6] 5d 29 28 [4-6] 5b [4-6] 5d 29 3b 7d } // Exec method -> {F[F](F[F])(F[F]);}
      $s2 = { 7b 72 65 74 75 72 6e 20 [4-6] 20 25 20 28 [4-6] 2b [4-6] 29 3b 7d } // Modulo OP -> {return F % (F+F);} 
      $s3 = { 7b [4-6] 20 3d 20 [4-6] 28 [4-6] 29 2e 73 70 6c 69 74 28 [4-6] 29 3b 7d } // Split OP -> {F = F(F).split(F);}
      $s4 = { 7b 72 65 74 75 72 6e 20 [4-6] 2e 63 68 61 72 41 74 28 [4-6] 29 3b 7d} // Getchar OP -> {return F.charAt(F);} 
      $s5 = { 7b [4-6] 5b [4-6] 5d 20 3d 20 [4-6] 5b [4-6] 5b [4-6] 5d 5d 3b 7d }  // GetIndex OP -> {F[F] = F[F[F]];} 
   condition:
      filesize > 1KB and 2 of them 
}

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


rule SUSP_JSframework_fingerprint2
{
	meta:
		author      = "@imp0rtp3"
		description = "fingerprint2 JS library signature, can be used for legitimate purposes"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:

		$m1 = "valentin.vasilyev"
		$m2 = "Valentin Vasilyev"
		$m3 = "Fingerprintjs2"
		$a1 = "2277735313"
		$a2 = "289559509"
		$a3 = "1291169091"
		$a4 = "658871167"
		$a5 = "excludeIOS11"
		$a6 = "sortPluginsFor"
		$a7 = "Cwm fjordbank glyphs vext quiz, \\ud83d\\ude03"
		$a8 = "varyinTexCoordinate"
		$a9 = "webgl alpha bits:"
		$a10 = "WEBKIT_EXT_texture_filter_anisotropic"
		$a11 = "mmmmmmmmmmlli"
		$a12 = "'new Fingerprint()' is deprecated, see https://github.com/Valve/fingerprintjs2#upgrade-guide-from-182-to-200"
		$b1 = "AcroPDF.PDF"
		$b2 = "Adodb.Stream"
		$b3 = "AgControl.AgControl"
		$b4 = "DevalVRXCtrl.DevalVRXCtrl.1"
		$b5 = "MacromediaFlashPaper.MacromediaFlashPaper"
		$b6 = "Msxml2.DOMDocument"
		$b7 = "Msxml2.XMLHTTP"
		$b8 = "PDF.PdfCtrl"
		$b9 = "QuickTime.QuickTime"
		$b10 = "QuickTimeCheckObject.QuickTimeCheck.1"
		$b11 = "RealPlayer"
		$b12 = "RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)"
		$b13 = "RealVideo.RealVideo(tm) ActiveX Control (32-bit)"
		$b14 = "Scripting.Dictionary"
		$b15 = "SWCtl.SWCtl"
		$b16 = "Shell.UIHelper"
		$b17 = "ShockwaveFlash.ShockwaveFlash"
		$b18 = "Skype.Detection"
		$b19 = "TDCCtl.TDCCtl"
		$b20 = "WMPlayer.OCX"
		$b21 = "rmocx.RealPlayer G2 Control"
		$b22 = "rmocx.RealPlayer G2 Control.1"

	condition:
		filesize < 1000000 and (
			(
				all of ($m*) and 
				2 of ($a*)
			) 
			or 8 of ($a*)
			or (
				5 of ($a*)
				and 13 of ($b*)
			)
		)

}



rule SUSP_obfuscated_JS_obfuscatorio
{
	meta:
	
		author      = "@imp0rtp3"
		description = "Detect JS obfuscation done by the js obfuscator (often malicious)"
		reference   = "https://obfuscator.io"

	strings:

		// Beggining of the script
		$a1 = "var a0_0x"
		$a2 = /var _0x[a-f0-9]{4}/
		
		// Strings to search By number of occurences
		$b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/
		$b2 =/[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/
		$b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/
		$b4 = /!0x1[^\d\w]/
		$b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/
		$b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/
		
		// generic strings often used by the obfuscator
		$c1 = "))),function(){try{var _0x"
		$c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$c3 = "['atob']=function("
		$c4 = ")['replace'](/=+$/,'');var"
		$c5 = "return!![]"
		$c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
		$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
		$c8 = "while(!![])"
		$c9 = "while (!![])"

		// Strong strings
		$d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/
				
	condition:
		$a1 at 0 or
		$a2 at 0 or
		(
			filesize<1000000 and
			(
				(#b1 + #b2) > (filesize \ 200) or
				#b3 > 1 or
				#b4 > 10 or
				#b5 > (filesize \ 2000) or
				#b6 > (filesize \ 200) or
				3 of ($c*) or
				$d1
			)
		)
}

