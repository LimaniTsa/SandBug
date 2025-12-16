rule UPX_Packed_File
{
    meta:
        description = "UPX packed executable"
        severity = "low"

    strings:
        $a = "UPX0"
        $b = "UPX1"

    condition:
        all of them
}
