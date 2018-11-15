def decrypt_str(encbuf):
    encbuf = encbuf.decode("hex")

    v3 = 0
    tmp_buf = []
    while len(encbuf) > v3:
        pb = v3 ^ ((v3 ^ ((v3 ^ ord(encbuf[v3-1])) - v3)) - v3)
        tmp_buf.append(chr(pb))
        v3 += 1

    plainbuf = "".join(tmp_buf[1:]) + tmp_buf[0]

    return plainbuf


print decrypt_str("6A6F796A607A445A4B768F6C")
print decrypt_str("466F7F647B697469817691899E73")
