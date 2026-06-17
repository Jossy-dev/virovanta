rule vv_html_meta_refresh_redirector
{
  meta:
    author = "ViroVanta"
    category = "web"
    severity = "medium"
    confidence = "medium"
    scope = "file"
    rationale = "HTML redirectors frequently hide behind meta refresh or JavaScript location changes to push users toward an external landing page."
  strings:
    $m1 = "<meta http-equiv=\"refresh\"" ascii nocase
    $m2 = "url=http" ascii nocase
    $m3 = "window.location" ascii nocase
    $m4 = "document.location" ascii nocase
    $m5 = "location.href" ascii nocase
    $m6 = "setTimeout(" ascii nocase
    $m7 = "atob(" ascii nocase
    $m8 = "String.fromCharCode" ascii nocase
  condition:
    filesize < 3MB and
    (
      ($m1 and $m2) or
      (1 of ($m3, $m4, $m5) and 1 of ($m6, $m7, $m8))
    )
}
