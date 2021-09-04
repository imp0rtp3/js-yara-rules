rule crime_JS_Chromelogger
{
	meta:
		author      = "@imp0rtp3"
		description = "Chromelogger Add-on YARA"
		reference   = "https://github.com/vxunderground/MalwareSourceCode/blob/main/Javascript/Trojan.Javascript.ChromeLogger.a.zip"

	strings:
		$a1 = "spyjs_saveData"
		$a2 = "spyjs_getInput"
		$a3 = "').unbind('change')"
		$a4 = "log1.php?values="
		$a5 = "spyjs_refreshEvents"
		$a6 = "http://127.0.0.1/server/"

	condition:
		4 of ($*)
}