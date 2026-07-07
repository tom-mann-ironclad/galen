rule GALEN_Test_EICAR_Dropper_Or_Downloader
{
    meta:
        description = "Detects test files that embed or download the EICAR test payload"
        category = "test-file"
        score = 90

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
        $url1 = "secure.eicar.org/eicar.com" ascii
        $name1 = "eicar.com" ascii
        $wget = "wget" ascii
        $curl = "curl" ascii
        $shell = "#!/bin/bash" ascii
        $system = "system" ascii

    condition:
        $eicar and $name1 and
        (
            $url1 or
            $wget or
            $curl or
            $shell or
            $system
        )
}
