rule GALEN_Test_AMTSO_PotentiallyUnwanted_Application
{
    meta:
        description = "Detects the AMTSO Potentially Unwanted Application test file"
        category = "test-file"
        family = "AMTSO-PUA-Test"
        score = 80

    strings:
        $mz = { 4D 5A }
        $amtso_feature_check = "http://www.amtso.org/feature-settings-check.html" ascii
        $amtso_security_text = "For more security feature tests, please visit:" ascii

    condition:
        $mz at 0 and
        all of ($amtso_*)
}
