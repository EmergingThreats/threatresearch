import struct

dwords = [0xE56E246F, 0x83600269, 0x2166A063, 0x8F5C8E5D]
buf = "".join([struct.pack("I", dword) for dword in dwords])
buf += struct.pack("H", 0x8C5B)

plainbuf = []
i = 0
j = 0
while True:
    enc_word = struct.unpack("H", buf[j:j+2])[0]

    # math snip

    v64 = (~((~(enc_word) ^ 0x7942) + 1) - i - 36192) & 0xffff
    v65 = (i + (((v64 << 15) | (v64 >> 1)) & 0xFFFF) + 54873) & 0xffff
    v66 = ((i + (((v65 << 9) | (v65 >> 7)) & 0xFFFF)) << 7) & 0xffff
    plain_word = ((16 * ((v66 | ((i + ((v65 << 9) | (v65 >> 7))) >> 9)) - 3641)) | (((v66 | ((i + ((v65 << 9) | (v65 >> 7))) >> 9)) - 3641) >> 12)) & 0xffff

    # math snip 

    plainbuf.append(chr(plain_word & 0xff))
    
    i += 1
    if i >= (len(buf)/2):
        break

    j += 2

print "".join(plainbuf)
