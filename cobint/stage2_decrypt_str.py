def get_buf(addr, buf_len):
    buf = []
    for i in range(buf_len):
        buf.append(chr(Byte(addr+i)))
        
    return "".join(buf)
    
xor_key = get_buf(0x10004040, 64)
encbuf = get_buf(0x10004000, 64)

plainbuf = []
for i, ch in enumerate(encbuf):
    plain_byte = ord(ch) ^ ord(xor_key[i % len(xor_key)])
    if plain_byte == 0:
        break
        
    plainbuf.append(chr(plain_byte))
    
print "".join(plainbuf)
