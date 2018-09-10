import struct

image_base = 0x1a1f0000
encbuf_addr = image_base + 1051
xor_key = struct.pack("I", 0x4A015756)
    
encbuf = []
for i in range(1000):
    enc_byte = Byte(encbuf_addr+i)       
    encbuf.append(chr(enc_byte))

plainbuf = []

k = 0
for i, enc_byte in enumerate(encbuf):
    plain_byte = ord(enc_byte) ^ ord(xor_key[k % len(xor_key)])
    k += 1
    if plain_byte == 0:
        k = 0
    
    plainbuf.append(chr(plain_byte))
    
strings = "".join(plainbuf).split("\x00")
