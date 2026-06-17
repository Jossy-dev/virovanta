rule vv_ps_encoded_command_dropper
{
  meta:
    author = "ViroVanta"
    category = "script"
    severity = "high"
    confidence = "high"
    scope = "file"
    rationale = "Encoded PowerShell paired with base64 decoding and download execution is a common malware delivery pattern."
  strings:
    $enc1 = "-enc " ascii nocase
    $enc2 = "-encodedcommand" ascii nocase
    $decode1 = "FromBase64String" ascii nocase
    $decode2 = "Text.Encoding]::Unicode.GetString" ascii nocase
    $exec1 = "Invoke-Expression" ascii nocase
    $exec2 = "IEX(" ascii nocase
    $net1 = "Net.WebClient" ascii nocase
    $net2 = "DownloadString(" ascii nocase
    $net3 = "DownloadFile(" ascii nocase
    $net4 = "Invoke-WebRequest" ascii nocase
  condition:
    filesize < 3MB and
    1 of ($enc*) and
    (1 of ($decode*) or 1 of ($exec*)) and
    1 of ($net*)
}

rule vv_ps_lolbin_download_cradle
{
  meta:
    author = "ViroVanta"
    category = "script"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "Living-off-the-land download cradles often combine a LOLBIN, a remote fetch, and stealth flags before launching a payload."
  strings:
    $lol1 = "powershell.exe" ascii nocase
    $lol2 = "cmd.exe /c" ascii nocase
    $lol3 = "mshta" ascii nocase
    $lol4 = "rundll32" ascii nocase
    $lol5 = "regsvr32" ascii nocase
    $lol6 = "certutil" ascii nocase
    $lol7 = "bitsadmin" ascii nocase
    $net1 = "http://" ascii nocase
    $net2 = "https://" ascii nocase
    $net3 = "URLDownloadToFile" ascii nocase
    $net4 = "DownloadString" ascii nocase
    $net5 = "DownloadFile" ascii nocase
    $stealth1 = "-nop" ascii nocase
    $stealth2 = "-windowstyle hidden" ascii nocase
    $stealth3 = "-w hidden" ascii nocase
    $stealth4 = "Start-Process" ascii nocase
  condition:
    filesize < 3MB and
    1 of ($lol*) and
    2 of ($net*) and
    1 of ($stealth*)
}
