rule Ransomware_Indicators
{
    meta:
        description = "Common ransomware indicators"
        severity = "high"

    strings:
        $a = "your files have been encrypted" nocase
        $b = ".locked" nocase
        $c = ".encrypted" nocase

    condition:
        any of them
}
