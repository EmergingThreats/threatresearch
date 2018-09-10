import base64
import struct
import sys

fp = open(sys.argv[1], "rb")
data = fp.read()
fp.close()

round1 = []

k = 0
while k < len(data):
    ch = ord(data[k])
    
    if ch <= 0x20 or ch == 0x2e or ch == 0x2c:
        k += 1
        ch = ord(data[k]) - 0x20

    k += 1
    round1.append(chr(ch))

round2 = base64.b64decode("".join(round1))

round3 = []
xor_key = 0x4A015756 
dword1 = struct.unpack("I", round2[0:4])[0]
for i in range(4, len(round2), 4):
    dword2 = struct.unpack("I", round2[i:i+4])[0]
    plain_dword = (xor_key ^ (dword2 - dword1)) & 0xffffffff
    round3.append(struct.pack("I", plain_dword))
    xor_key = dword1
    dword1 = dword2

mz = "".join(round3)[4:]
