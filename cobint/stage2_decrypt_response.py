import re
import struct
import sys


def round3_trans(buf):
    out = [0]*len(buf)

    k = 0 
    j = 0 
    i = 8 

    while j < len(buf):
        math1 = ord(buf[j]) - 0x61
    
        if ord(buf[j]) == 0x7a:
            j += 1
            math2 = 7 * (ord(buf[j]) - 0x60) / 0x1a
            if math2 > 6:
                math2 = 6 
            math1 = math2 + 0x19

        if i < 5:
            out[k] = (out[k] | math1 >> (5 - i)) & 0xff
            k += 1
            i = 8 - (5 - i)
            out[k] = (math1 << i) & 0xff
        else:
            i -= 5
            out[k] = (out[k] | math1 << i) & 0xff

        j += 1

    out = [chr(b & 0xff) for b in out]

    return "".join(out)


fp = open(sys.argv[1], "rb")
html = fp.read()
fp.close()

fp = open(sys.argv[2], "rb")
xor_key = fp.read()
fp.close()

html = html.strip()

# remove html tags
round1 = re.sub(r'<[^>]*>', '', html)

# lower case
round2 = round1.lower()

# remove non a-z characters
round3 = re.sub(r'[^a-z]', '', round2)

# some kind of character transform
round4 = round3_trans(round3).strip("\x00")

# xor with hardcoded xor_key
round5 = []

for i, b in enumerate(round4):
    plain_byte = ord(b) ^ ord(xor_key[i % len(xor_key)])
    round5.append(chr(plain_byte))

round5 = "".join(round5)

# another round of xor 
# key len is indicated by the last byte
key_len = ord(round5[-1])
key_offset = len(round5) - key_len - 1

round6 = []
for i in range(len(round5)):
    plain_byte = ord(round5[i]) ^ ord(round5[key_offset + (i % key_len)])
    round6.append(chr(plain_byte))

round6 = "".join(round6)

command = ord(round6[0])
print "command: %d" % command
command_id = struct.unpack("I", round6[1:5])[0]
print "command id: %d" % command_id

command_data = round6[5:]

module_hash = struct.unpack("I", command_data[0:4])[0]
print "module hash: 0x%x" % module_hash
module_len = struct.unpack("I", command_data[4:8])[0]
print "module len: %d" % module_len
module = command_data[8:8+module_len]

command_data = command_data[8+module_len:]

entry_point = struct.unpack("I", command_data[0:4])[0]
print "entry point: 0x%x" % entry_point
unknown_dword = struct.unpack("I", command_data[4:8])[0]
print "unknown dword: 0x%x" % unknown_dword
remaining_data = command_data[8:]
print "remaining data: %s" % remaining_data

fp = open("module_%d_%d" % (command_id, module_len), "wb")
fp.write(module)
fp.close()
