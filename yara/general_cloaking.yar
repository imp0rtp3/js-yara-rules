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
