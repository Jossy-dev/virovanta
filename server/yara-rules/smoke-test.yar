rule vv_smoke_test
{
  meta:
    author = "ViroVanta"
    category = "smoke"
    severity = "medium"
    confidence = "high"
    scope = "validation"
    rationale = "Confirms local YARA execution works before larger rule-pack validation."
  strings:
    $a = "ViroVanta YARA smoke test"
  condition:
    $a
}
