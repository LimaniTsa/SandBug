rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell-based file download commands"
        severity = "medium"

    strings:
        $ps = "powershell" nocase
        $dl = "Invoke-WebRequest" nocase
        $http = "http://" nocase

    condition:
        all of them
}
