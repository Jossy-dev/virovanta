rule vv_pdf_active_content_launch
{
  meta:
    author = "ViroVanta"
    category = "document"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "Suspicious PDF actions such as JavaScript, Launch, OpenAction, or embedded files deserve extra scrutiny in phishing and loader workflows."
  strings:
    $p1 = "/OpenAction" ascii
    $p2 = "/AA" ascii
    $p3 = "/JavaScript" ascii
    $p4 = "/JS" ascii
    $p5 = "/Launch" ascii
    $p6 = "/EmbeddedFile" ascii
    $p7 = "/RichMedia" ascii
    $p8 = "/SubmitForm" ascii
  condition:
    filesize < 25MB and
    (1 of ($p1, $p2, $p5, $p6, $p7)) and
    3 of ($p*)
}

rule vv_html_credential_harvest_kit
{
  meta:
    author = "ViroVanta"
    category = "web"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "Credential harvest kits often pair a password form, external submission, brand lure, and urgency text inside a compact HTML payload."
  strings:
    $form1 = "<form" ascii nocase
    $pass1 = "type=\"password\"" ascii nocase
    $pass2 = "name=\"passwd\"" ascii nocase
    $pass3 = "name=\"password\"" ascii nocase
    $post1 = "method=\"post\"" ascii nocase
    $post2 = "action=\"http" ascii nocase
    $post3 = "fetch(\"http" ascii nocase
    $lure1 = "verify your account" ascii nocase
    $lure2 = "password expires today" ascii nocase
    $lure3 = "mailbox has been upgraded" ascii nocase
    $brand1 = "office365" ascii nocase
    $brand2 = "microsoft 365" ascii nocase
    $brand3 = "outlook web app" ascii nocase
    $brand4 = "okta verify" ascii nocase
    $brand5 = "onedrive" ascii nocase
  condition:
    filesize < 3MB and
    $form1 and
    1 of ($pass*) and
    1 of ($post*) and
    1 of ($lure*) and
    1 of ($brand*)
}
