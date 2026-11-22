rule MiniAV_PowerShell_Encoded
{
    meta:
        description = "PowerShell encoded command indicators"
        version = "0.3.0"
    strings:
        $a = "powershell -enc" nocase ascii wide
        $b = "powershell.exe -enc" nocase ascii wide
        $c = "-EncodedCommand" nocase ascii wide
    condition:
        any of them
}

rule MiniAV_Process_Injection_Indicators
{
    meta:
        description = "Common process injection API combinations"
        version = "0.3.0"
    strings:
        $a = "WriteProcessMemory" ascii wide
        $b = "CreateRemoteThread" ascii wide
        $c = "VirtualAllocEx" ascii wide
        $d = "NtMapViewOfSection" ascii wide
    condition:
        2 of them
}

rule MiniAV_Suspicious_LOLBins
{
    meta:
        description = "Multiple Windows living-off-the-land execution indicators"
        version = "0.3.0"
    strings:
        $a = "mshta.exe" nocase ascii wide
        $b = "regsvr32.exe" nocase ascii wide
        $c = "rundll32.exe" nocase ascii wide
        $d = "certutil -urlcache" nocase ascii wide
    condition:
        2 of them
}
