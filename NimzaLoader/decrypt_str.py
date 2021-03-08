def decrypt(addr, key):
    encbuf_len = get_wide_word(addr)
    encbuf = get_bytes(addr+16, encbuf_len)
    
    plainbuf = []
    session_key = key
    for eb in encbuf:
        for kb in struct.pack("I", session_key):
            eb ^= kb
        
        plainbuf.append(chr(eb))
        session_key += 1
        
    print(plainbuf)
    
    
#decrypt(0xA070C0, 0x253988D0)
