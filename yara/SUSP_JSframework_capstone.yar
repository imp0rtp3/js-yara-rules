rule SUSP_JSframework_capstone
{
	meta:
		author      = "@imp0rtp3"
		description = "Detects use of the capstone.js framework (can be used for exploit, not necessarily malicious)"
		reference   = "https://alexaltea.github.io/capstone.js/"
		refenrce_2  = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"


	strings:
		$a1 = "_cs_insn_name"
		$a2 = "Module = MCapstone"
		$a3 = "var MCapstone"
		$a4 = "Wrapper made by Alexandro Sanchez Bach."
		$a5 = "MCapstone.ccall"
		$a6 = "MCapstone.Pointer_stringify"
		$a7 = "Capstone.js: Function cs_option failed"
		$a8 = "ARM64_SYSREG_ID_ISAR5_EL1"

	condition:
		filesize > 1MB and
		filesize<10MB and
		4 of them

}