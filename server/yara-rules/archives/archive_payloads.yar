rule vv_archive_script_or_shortcut_payload
{
  meta:
    author = "ViroVanta"
    category = "archive"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "Phishing archives frequently contain script or shortcut payloads named like invoices, remittances, scans, or document bait."
  strings:
    $zip = { 50 4B 03 04 }
    $ext1 = ".js" ascii nocase
    $ext2 = ".jse" ascii nocase
    $ext3 = ".vbs" ascii nocase
    $ext4 = ".vbe" ascii nocase
    $ext5 = ".ps1" ascii nocase
    $ext6 = ".bat" ascii nocase
    $ext7 = ".cmd" ascii nocase
    $ext8 = ".lnk" ascii nocase
    $ext9 = ".hta" ascii nocase
    $lure1 = "invoice" ascii nocase
    $lure2 = "payment" ascii nocase
    $lure3 = "remittance" ascii nocase
    $lure4 = "document" ascii nocase
    $lure5 = "scan" ascii nocase
    $lure6 = "rfq" ascii nocase
  condition:
    filesize < 50MB and
    $zip at 0 and
    1 of ($ext*) and
    1 of ($lure*)
}

rule vv_archive_nested_disk_image_bait
{
  meta:
    author = "ViroVanta"
    category = "archive"
    severity = "medium"
    confidence = "medium"
    scope = "file"
    rationale = "Nested delivery using disk-image or multi-layer archive extensions is common in modern phishing chains because it weakens simple attachment blocking."
  strings:
    $zip = { 50 4B 03 04 }
    $n1 = ".zip" ascii nocase
    $n2 = ".rar" ascii nocase
    $n3 = ".7z" ascii nocase
    $n4 = ".iso" ascii nocase
    $n5 = ".img" ascii nocase
    $n6 = ".one" ascii nocase
    $n7 = ".html" ascii nocase
    $n8 = ".lnk" ascii nocase
    $bait1 = "invoice" ascii nocase
    $bait2 = "shipping" ascii nocase
    $bait3 = "statement" ascii nocase
    $bait4 = "secure document" ascii nocase
  condition:
    filesize < 50MB and
    $zip at 0 and
    2 of ($n*) and
    1 of ($bait*)
}
