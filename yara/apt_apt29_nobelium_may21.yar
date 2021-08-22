
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

