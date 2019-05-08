def decrypt_string(offset):
    chunk = 0x401288+8*offset

    xor = Word(chunk)
    size = Word(chunk+2)
    addr = Dword(chunk+4)

    enc_buf = []
    for i in range(size):
        enc_buf.append(Byte(addr + i))

    plain = []
    for i in range(size):
        byte = chr((xor ^ enc_buf[i]) & 0xff)
        plain.append(byte)

    return "".join(plain)

for i in range(183):
    print "%d: %s" % (i, decrypt_string(i))
