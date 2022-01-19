import sys

key = bytearray("trump2020".encode("utf-16le"))
data = bytearray(sys.stdin.read())

out = bytearray()
lkey = len(key)
ldata = len(data)

for i in xrange(ldata):
    out.append(((data[i] ^ key[i % lkey]) - data[(i + 1) % ldata]) & 0xff)

sys.stdout.write(out[:-1])
