def decrypt_comms(key, encbuf):
    key = key.encode("hex").upper()
    encbuf = encbuf.decode("hex")

    fp = open("table", "rb")
    table = fp.read()
    fp.close()
    
    g_vals1 = 256 * 0
    g_vals2 = 256 * 1 
    g_vals3 = 256 * 2 
    g_vals4 = 256 * 3 
    g_vals5 = 256 * 4 
    g_vals6 = 256 * 5

    plainbuf = []
    for i in range(len(encbuf)):
        v4 = ord(key[i % len(key)])
        
        pb = ord(table[g_vals1 + v4]) ^ ord(table[g_vals2 + v4]) ^ ord(table[g_vals3 + v4]) ^ ord(table[g_vals4 + v4]) ^ ord(table[g_vals5 + v4]) ^ ord(table[g_vals6 + v4]) ^ v4 ^ ord(encbuf[i]) ^ v4
        
        plainbuf.append(chr(pb))
        
    return "".join(plainbuf)


key1 = "Fx@%gJ_2oK"
key2 = "AC8FFF33D07229BF84E7A429CADC33BFEAE7AC4A87AE33ACEAAC8192A68C55A6"
key3 = "&LmcF#7R2m"

key = key1 + key2 + key3

print decrypt_comms(key, "CF8B77")
print decrypt_comms(key, "D9BD68ABF53C3914A248EC603E9CD96FE194A624D599ADFB89DDD0E9D2EFA3E88786FE89A2D6FD5FF91887318E4C8919D730D5E388D88FA1D5358C6FA5ED89D78A4BFD6CA0FEA397D5D5A1FAFCFE8D86D230D1E3D748D2E8D731896BA696AD8DFDACD698FA")
print decrypt_comms(key, "D29A79D6CD2F47389A66BB5F2891D64C8A87F05AE3E1C6C5CBA4A79AA5ECA29F8E8C8FFCA6A2892B8B6E")
