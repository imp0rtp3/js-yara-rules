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

