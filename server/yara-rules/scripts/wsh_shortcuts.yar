rule vv_wsh_dropper_components
{
  meta:
    author = "ViroVanta"
    category = "script"
    severity = "high"
    confidence = "high"
    scope = "file"
    rationale = "Windows Script Host malware often combines COM objects for network fetch, file writes, and local execution."
  strings:
    $c1 = "CreateObject(\"WScript.Shell\")" ascii nocase
    $c2 = "CreateObject(\"Scripting.FileSystemObject\")" ascii nocase
    $c3 = "CreateObject(\"MSXML2.XMLHTTP\")" ascii nocase
    $c4 = "CreateObject(\"ADODB.Stream\")" ascii nocase
    $c5 = ".SaveToFile" ascii nocase
    $c6 = ".Run " ascii nocase
    $c7 = ".Exec(" ascii nocase
    $c8 = "ExpandEnvironmentStrings" ascii nocase
  condition:
    filesize < 3MB and
    4 of ($c*)
}

rule vv_lnk_lolbin_launcher
{
  meta:
    author = "ViroVanta"
    category = "shortcut"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "Malicious shortcut files often embed a LOLBIN target plus encoded or remote-fetch arguments."
  strings:
    $header = { 4C 00 00 00 }
    $lol1 = "powershell.exe" ascii wide nocase
    $lol2 = "cmd.exe" ascii wide nocase
    $lol3 = "mshta.exe" ascii wide nocase
    $lol4 = "wscript.exe" ascii wide nocase
    $lol5 = "cscript.exe" ascii wide nocase
    $lol6 = "rundll32.exe" ascii wide nocase
    $arg1 = "-enc" ascii wide nocase
    $arg2 = "/c " ascii wide nocase
    $arg3 = "http://" ascii wide nocase
    $arg4 = "https://" ascii wide nocase
    $arg5 = "%COMSPEC%" ascii wide nocase
  condition:
    filesize < 5MB and
    $header at 0 and
    1 of ($lol*) and
    1 of ($arg*)
}
