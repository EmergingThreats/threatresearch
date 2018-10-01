def decrypt_str(addr, length, key):
    encbuf = []
    for i in range(length):
        encbuf.append(Dword(addr+4*i))
    
    plainbuf = []
    for i, b in enumerate(encbuf):
        pb = (b - (i + 1) - key) & 0xff
        plainbuf.append(chr(pb))

    return "".join(plainbuf)
