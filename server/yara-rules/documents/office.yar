rule vv_office_macro_autoexec_downloader
{
  meta:
    author = "ViroVanta"
    category = "document"
    severity = "high"
    confidence = "high"
    scope = "file"
    rationale = "Office files that pair auto-executing macro hooks with downloader or shell functionality are strong malware indicators."
  strings:
    $auto1 = "AutoOpen" ascii nocase
    $auto2 = "Document_Open" ascii nocase
    $auto3 = "Workbook_Open" ascii nocase
    $auto4 = "Auto_Close" ascii nocase
    $mal1 = "CreateObject(" ascii nocase
    $mal2 = "WScript.Shell" ascii nocase
    $mal3 = "PowerShell" ascii nocase
    $mal4 = "URLDownloadToFile" ascii nocase
    $mal5 = "XMLHTTP" ascii nocase
    $mal6 = "ADODB.Stream" ascii nocase
    $mal7 = "Shell(" ascii nocase
  condition:
    filesize < 10MB and
    1 of ($auto*) and
    3 of ($mal*)
}

rule vv_office_dde_command_exec
{
  meta:
    author = "ViroVanta"
    category = "document"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "DDE abuse can launch system commands directly from document content and remains a durable phishing technique."
  strings:
    $dde = "DDEAUTO" ascii nocase
    $cmd1 = "cmd.exe" ascii nocase
    $cmd2 = "powershell" ascii nocase
    $cmd3 = "mshta" ascii nocase
    $cmd4 = "rundll32" ascii nocase
    $cmd5 = "http://" ascii nocase
    $cmd6 = "https://" ascii nocase
    $cmd7 = "-enc" ascii nocase
  condition:
    filesize < 10MB and
    $dde and
    2 of ($cmd*)
}
