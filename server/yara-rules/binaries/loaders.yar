rule vv_dotnet_reflective_loader
{
  meta:
    author = "ViroVanta"
    category = "binary"
    severity = "high"
    confidence = "high"
    scope = "file"
    rationale = "Managed loaders often combine in-memory assembly loading, base64 decoding, and classic injection APIs to unpack later-stage malware."
  strings:
    $m1 = "System.Reflection.Assembly" ascii nocase
    $m2 = "Assembly.Load" ascii nocase
    $m3 = "FromBase64String" ascii nocase
    $m4 = "Convert.FromBase64String" ascii nocase
    $m5 = "VirtualAlloc" ascii nocase
    $m6 = "WriteProcessMemory" ascii nocase
    $m7 = "CreateRemoteThread" ascii nocase
    $m8 = "GetProcAddress" ascii nocase
    $m9 = "kernel32.dll" ascii nocase
  condition:
    filesize < 20MB and
    2 of ($m1, $m2, $m3, $m4) and
    3 of ($m5, $m6, $m7, $m8, $m9)
}

rule vv_native_shellcode_loader_cluster
{
  meta:
    author = "ViroVanta"
    category = "binary"
    severity = "high"
    confidence = "medium"
    scope = "file"
    rationale = "Clusters of allocation, memory-write, and thread-launch APIs are common in shellcode loaders and process-injection tooling."
  strings:
    $n1 = "VirtualAlloc" ascii nocase
    $n2 = "VirtualProtect" ascii nocase
    $n3 = "WriteProcessMemory" ascii nocase
    $n4 = "CreateThread" ascii nocase
    $n5 = "CreateRemoteThread" ascii nocase
    $n6 = "NtAllocateVirtualMemory" ascii nocase
    $n7 = "RtlMoveMemory" ascii nocase
    $n8 = "ZwUnmapViewOfSection" ascii nocase
    $n9 = "IsDebuggerPresent" ascii nocase
    $n10 = "kernel32.dll" ascii nocase
    $n11 = "ntdll.dll" ascii nocase
  condition:
    filesize < 25MB and
    4 of ($n*) and
    1 of ($n10, $n11)
}
