import sys
import struct
import re


def decode_int(s):                           # MSIL bytecode for "ldc XX"
    if ord(s[0]) == 0x20:                    # ldc.i4 <int32>
        i = struct.unpack("<L", s[1:5])[0]
    elif ord(s[0]) == 0x1f:                  # ldc.i4.s <int8> (short form)
        i = ord(s[1])
    elif 0x16 <= ord(s[0]) < 0x1f:           # ldc.i4.[0-8]
        i = ord(s[0]) - 0x16
    else:
        print "couldn't decode int from %d" % ord(s[0])

    return i


array_re = re.compile(r"(?P<num>\x20....|\x1f.|[\x16-\x1e])"   # ldc XX
                      r"\x8d.\x00\x00\x01"                     # newarr (TypeRef) x
                      r"(?P<array>(\x25(\x20....|\x1f.|[\x16-\x1e])"
                      r"(\x20....|\x1f.|[\x16-\x1e])\x9d)+)"   # (see item_re)
                      r"\x73.\x00\x00\x0a"                     # newobj (MemberRef) x
                      r"\x2a",                                 # ret
                      flags=re.S | re.M)

item_re = re.compile(r"\x25"                                   # dup
                     r"(?P<index>\x20....|\x1f.|[\x16-\x1e])"  # ldc XX
                     r"(?P<value>\x20....|\x1f.|[\x16-\x1e])"  #
                     r"\x9d",                                  # stelem.i2
                     flags=re.S | re.M)

data = sys.stdin.read()

n = 0

for match in array_re.finditer(data):
    num = decode_int(match.group("num"))
    array = match.group("array")
    arr = {}

    for item in item_re.finditer(array):
        index = decode_int(item.group("index"))
        val = decode_int(item.group("value"))

        if 0 <= index < num and 0 <= val < 256:
            arr[index] = val  # multiple assignments for each; want the last

        else:
            print "array[%d] = %d not in expected range" % (index, val)

    decoded = ""

    for i in xrange(num):
        decoded += chr(arr[i])

    print "[%d] : %s" % (n, decoded)
    n += 1
