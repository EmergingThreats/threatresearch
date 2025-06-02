rule brooxml_hunting {
    meta:
        description = "Detects Microsoft OOXML files with prepended data/manipulated header"
        author = "Proofpoint"
        category = "hunting"
    strings:
        $pk_ooxml_magic = {50 4b 03 04 [22] 13 00 [2] 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c}

        $pk_0102 = {50 4b 01 02}
        $pk_0304 = {50 4b 03 04}
        $pk_0506 = {50 4b 05 06}
        $pk_0708 = {50 4b 07 08}

        $word = "word/"

        // Negations for FPs / unwanted file types
        $ole = {d0 cf 11 e0}
        $tef = {78 9f 3e 22}
    condition:
        $pk_ooxml_magic in (4..16384) and
        $pk_0506 in (16384..filesize) and
        #pk_0506 == 1 and
        #pk_0102 > 2 and
        #pk_0304 > 2 and
        $word and
        not ($pk_0102 at 0) and
        not ($pk_0304 at 0) and
        not ($pk_0506 at 0) and
        not ($pk_0708 at 0) and
        not ($ole at 0) and
        not (uint16(0) == 0x5a4d) and
        not ($tef at 0)
}

rule brooxml_phishing {
    meta:
        description = "Detects PDF and OOXML files leading to AiTM phishing"
        author = "Proofpoint"
        category = "phishing"
    strings:
        $hex1 = { 21 20 03 20 c3 be c3 bf 09 20 [0-1] 06 20 20 20 20 20 20 20 20 20 20 20 01 20 20 20 06 20 20 20 20 20 20 20 20 10 20 20 05 20 20 20 01 20 20 20 c3 be c3 bf c3 bf c3 bf }
        $docx = { 50 4b }
        $pdf = { 25 50 44 46 2d }
    condition:
        all of ($hex*) and (($docx at 0) or ($pdf at 0))
}