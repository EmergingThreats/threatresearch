rule zip_double_zip: fileformat
{
    meta:
        author = "keaton"
        date = "11/13/2024"
        description = "matching zip files where two or more zip files were cat'd together"
        ref = "https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/"
    strings:
        $pkeocd = {50 4b 05 06}
    condition:
        uint32be(0) == 0x504b0304 and
        #pkeocd > 1 and 
        uint32be(uint32(@pkeocd[#pkeocd] + 16)) != 0x504b0102
}