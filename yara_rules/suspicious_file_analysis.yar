import "pe"
import "elf"

rule Suspicious_Base64_Encoded_Strings
{
    meta:
        description = "Detects long suspicious Base64 strings, often used in malware for payloads"
        author = "SOC Analyst"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $b64
}

rule Powershell_EncodedCommand
{
    meta:
        description = "Detects PowerShell encoded commands"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-encodedcommand" nocase
    condition:
        1 of ($ps*)
}

rule Obfuscated_JS_Eval
{
    meta:
        description = "Detects eval-based obfuscated JavaScript"
    strings:
        $eval = "eval(unescape(" nocase
        $hex  = /\\x[0-9a-fA-F]{2}/
    condition:
        $eval or $hex
}

rule PE_File_Overlay_Anomaly
{
    meta:
        description = "Detects abnormally large PE overlay, used to hide payloads"
    condition:
        filesize > pe.overlay.offset + 102400
}

rule Packed_UPX
{
    meta:
        description = "Detects UPX packed files"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX2"
    condition:
        all of them
}

rule VBA_Macro_Suspicious
{
    meta:
        description = "Detects suspicious VBA macro keywords"
    strings:
        $a = "AutoOpen"
        $b = "AutoClose"
        $c = "Document_Open"
        $d = "Shell"
        $e = "CreateObject"
    condition:
        2 of ($a, $b, $c, $d, $e)
}

rule WScript_Execution
{
    meta:
        description = "Detects WScript execution, used in droppers"
    strings:
        $s1 = "WScript.Shell"
        $s2 = "WScript.Echo"
    condition:
        any of them
}

rule Invoke_WebRequest_Payload
{
    meta:
        description = "Detects PowerShell downloading a payload"
    strings:
        $w1 = "Invoke-WebRequest" nocase
        $w2 = "Invoke-Expression" nocase
        $url = /http(s)?:\/\/[^\s]+/
    condition:
        $w1 and $w2 and $url
}

rule DotNet_Assembly_Load
{
    meta:
        description = "Detects .NET reflection loading"
    strings:
        $load = "System.Reflection.Assembly::Load"
        $b64  = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $load and $b64
}

rule Common_Infostealer_Keywords
{
    meta:
        description = "Detects common keywords in infostealers"
    strings:
        $c1 = "Mozilla\\Firefox\\Profiles"
        $c2 = "wallet.dat"
        $c3 = "login data"
        $c4 = "passwords"
    condition:
        2 of them
}

rule Ransom_Note_Keywords
{
    meta:
        description = "Detects common ransomware ransom note keywords"
    strings:
        $msg1 = "Your files have been encrypted"
        $msg2 = "ransom"
        $msg3 = "decrypt"
        $msg4 = "Bitcoin"
        $msg5 = "TOR browser"
    condition:
        3 of them
}

rule WannaCry_KillSwitch
{
    meta:
        description = "WannaCry known kill-switch domain"
    strings:
        $url = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    condition:
        $url
}

rule CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon string"
    strings:
        $s1 = "BeaconEye"
        $s2 = "sleep"
        $s3 = /https?:\/\/[A-Za-z0-9\-\.]+\/[A-Za-z0-9\-]+/
    condition:
        $s1 or ($s2 and $s3)
}

rule LokiBot_Indicators
{
    meta:
        description = "Detects LokiBot string artifacts"
    strings:
        $l1 = "Software\\LokiBot"
        $l2 = "POST /gate.php HTTP/1.1"
    condition:
        any of them
}

rule AsyncRAT_Fingerprint
{
    meta:
        description = "Detects AsyncRAT signature strings"
    strings:
        $a1 = "Client is connected!"
        $a2 = "Pastebin"
        $a3 = "ServerCertificateValidationCallback"
    condition:
        2 of them
}

rule AgentTesla_String_Pattern
{
    meta:
        description = "Detects AgentTesla common strings"
    strings:
        $ag1 = "Mozilla\\Firefox\\Profiles"
        $ag2 = "SmtpClient"
        $ag3 = "KeyLogger"
    condition:
        2 of them
}

rule NetWire_Mutex
{
    meta:
        description = "NetWire RAT mutex and paths"
    strings:
        $n1 = "Netwire"
        $n2 = "Software\\Netwire"
    condition:
        any of them
}

rule RemcosRAT_Keyword
{
    meta:
        description = "Detects strings associated with Remcos RAT"
    strings:
        $r1 = "Remcos"
        $r2 = "ClientSocket"
    condition:
        any of them
}

rule RedLineStealer_Traits
{
    meta:
        description = "Detects RedLine stealer strings"
    strings:
        $rs1 = "user+pass+token"
        $rs2 = "System.Text.Json"
        $rs3 = "RedLine"
    condition:
        2 of them
}

rule Formbook_String_Artifact
{
    meta:
        description = "Detects Formbook malware indicators"
    strings:
        $f1 = "PSTORE"
        $f2 = "WebBrowserPassView"
    condition:
        any of them
}

rule Shellcode_HEX_Pattern
{
    meta:
        description = "Detects raw shellcode byte patterns"
    strings:
        $sc1 = { FC 48 83 E4 F0 E8 }
        $sc2 = { 31 C0 64 8B 50 30 }
    condition:
        any of them
}


rule Process_Hollowing_Pattern
{
    meta:
        description = "Detects APIs used in process hollowing"
    strings:
        $a1 = "NtUnmapViewOfSection"
        $a2 = "WriteProcessMemory"
        $a3 = "SetThreadContext"
    condition:
        2 of them
}

rule XOR_Loop_Obfuscation
{
    meta:
        description = "Detects XOR loop used in obfuscated loaders"
    strings:
        $x1 = "xor eax, eax"
        $x2 = "inc ecx"
        $x3 = "jmp"
    condition:
        $x1 and $x2 and $x3
}

rule RC4_Algorithm
{
    meta:
        description = "Detects RC4 implementation in malware"
    strings:
        $rc4 = { 8D 4C 24 04 51 8B C1 33 C0 8A 14 08 }
    condition:
        $rc4
}

rule PDF_Embedded_JS
{
    meta:
        description = "Detects JavaScript embedded in PDF"
    strings:
        $js = "/JavaScript"
        $open = "/OpenAction"
    condition:
        all of them
}

rule PE_Suspicious_Section_Names
{
    meta:
        description = "Suspicious PE section names like .textbss, .packed"
    strings:
        $s1 = ".textbss"
        $s2 = ".packed"
        $s3 = ".evil"
    condition:
        any of them
}

rule Excel_DDEAttack
{
    meta:
        description = "Detects Excel DDE execution attack strings"
    strings:
        $dde = "DDEAUTO"
        $cmd = "cmd.exe"
    condition:
        all of them
}

rule Powershell_AMSI_Bypass
{
    meta:
        description = "Detects AMSI bypass in PowerShell"
    strings:
        $amsi = "AmsiUtils"
        $bypass = "Bypass"
    condition:
        all of them
}

rule AutoIt_Obfuscated_Script
{
    meta:
        description = "Detects obfuscated AutoIt script signature"
    strings:
        $auto = "#AutoIt3Wrapper"
        $obf  = "$a = ''"
    condition:
        all of them
}
