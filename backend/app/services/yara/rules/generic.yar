rule Suspicious_Command_Execution
{
    meta:
        description = "Suspicious command execution patterns"
        severity = "medium"

    strings:
        $a = "powershell" nocase
        $b = "cmd.exe" nocase
        $c = "wget " nocase
        $d = "curl " nocase

    condition:
        2 of them
}
