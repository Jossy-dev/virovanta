rule vv_js_activex_wscript_dropper
{
  meta:
    author = "ViroVanta"
    category = "script"
    severity = "high"
    confidence = "high"
    scope = "file"
    rationale = "JScript droppers frequently use ActiveX, XMLHTTP, and ADODB to fetch and write payloads before execution."
  strings:
    $a1 = "new ActiveXObject" ascii nocase
    $a2 = "WScript.Shell" ascii nocase
    $a3 = "Scripting.FileSystemObject" ascii nocase
    $a4 = "MSXML2.XMLHTTP" ascii nocase
    $a5 = "ADODB.Stream" ascii nocase
    $a6 = ".SaveToFile" ascii nocase
    $a7 = ".Run(" ascii nocase
    $a8 = "ExpandEnvironmentStrings" ascii nocase
  condition:
    filesize < 3MB and
    4 of ($a*)
}

rule vv_js_charcode_eval_obfuscation
{
  meta:
    author = "ViroVanta"
    category = "script"
    severity = "medium"
    confidence = "medium"
    scope = "file"
    rationale = "Heavy use of string deobfuscation plus dynamic execution is a common way to hide JavaScript droppers and redirectors."
  strings:
    $decode1 = "String.fromCharCode" ascii nocase
    $decode2 = "unescape(" ascii nocase
    $decode3 = "atob(" ascii nocase
    $decode4 = "decodeURIComponent(" ascii nocase
    $exec1 = "eval(" ascii nocase
    $exec2 = "Function(" ascii nocase
    $exec3 = "setTimeout(" ascii nocase
    $noise1 = "%u" ascii nocase
    $noise2 = "\\x" ascii nocase
  condition:
    filesize < 3MB and
    2 of ($decode*) and
    1 of ($exec*) and
    1 of ($noise*)
}
