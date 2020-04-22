def decrypt_str(addr, buf_len, wide=False):
    buf = []
    if wide:
        for i in range(0, buf_len*2, 2):
            buf.append(chr(get_wide_byte(addr+i)))
    else:
        for i in range(buf_len):
            buf.append(chr(get_wide_byte(addr+i)))
        
    # 2b5e50bc3077610128051bc3e657c3f0e331fb8fed2559c6596911890ea866ba
    key = "7Gl5et#0GoTI5VV94"
    plain = []
    for i, eb in enumerate(buf):
        pb = ord(eb) ^ ord(key[i % len(key)])
        plain.append(chr(pb))
        
    print("".join(plain))
