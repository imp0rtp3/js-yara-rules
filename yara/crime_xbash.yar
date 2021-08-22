
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
