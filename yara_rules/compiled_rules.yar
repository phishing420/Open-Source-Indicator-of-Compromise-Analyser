import "pe"
import "elf"
import "math"

rule Suspicious_Filenames {
    meta:
        author = "IoC analyser"
        description = "Detects malicious filenames"
        severity = "high"
    strings:
        $s1 = "malicious.exe" ascii
        $s2 = "payload.dll" ascii
        $s3 = "trojan.exe" ascii
    condition:
        any of ($s*)
}

rule Malicious_Headers {
    meta:
        author = "IoC analyser"
        description = "Malicious file headers"
        severity = "critical"
    strings:
        $h1 = { 4D 5A 90 00 03 00 00 00 }
        $h2 = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        any of them
}

rule PowerShell_Threats {
    meta:
        author = "IoC analyser"
        description = "Malicious PowerShell patterns"
        severity = "high"
    strings:
        $ps1 = "powershell.exe -nop -w hidden -c" ascii
        $ps2 = "Invoke-Expression" ascii
    condition:
        any of them
}

rule Network_Threats {
    meta:
        author = "IoC analyser"
        description = "Suspicious network activity"
        severity = "high"
    strings:
        $n1 = "nc.exe -e" ascii
        $n2 = "curl http://" ascii
    condition:
        any of them
}

rule PE_Anomalies {
    meta:
        author = "IoC analyser"
        description = "PE file manipulation"
        severity = "high"
    strings:
        $valloc = "VirtualAlloc" ascii
        $hidden = ".hidden" ascii
    condition:
        pe.is_pe and any of them
}

rule AntiAnalysis_Techniques {
    meta:
        author = "IoC analyser"
        description = "Anti-analysis methods"
        severity = "high"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "VMware" ascii
        $a3 = "VirtualBox" ascii
    condition:
        any of them
}

rule Fileless_Techniques {
    meta:
        author = "IoC analyser"
        description = "Fileless execution patterns"
        severity = "high"
    strings:
        $f1 = "regsvr32.exe" ascii
        $f2 = "mshta.exe" ascii
    condition:
        any of them
}

rule Obfuscation_Methods {
    meta:
        author = "IoC analyser"
        description = "Code obfuscation patterns"
        severity = "medium"
    strings:
        $o1 = { 66 ?? 8B ?? 81 ?? ?? ?? ?? ?? }
        $o2 = "base64_decode" ascii
    condition:
        any of them
}
