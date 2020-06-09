import binascii
import hashlib
import struct
import sys
import zlib

from Crypto.Cipher import ARC4


def ror(num, count, size):
    return ((num >> count) | (num << (size-count)))


def decrypt_header16(header):
    outbuf = []

    key = struct.unpack("I", header[0:4])[0]
    outbuf.append(header[0:4])

    for i in range(4, 16):
        pb = (ord(header[i]) ^ ror(key, i, 32)) & 0xff
        outbuf.append(chr(pb))

    header = "".join(outbuf)

    return header


def check_header16(data):
    header16 = {}
    print "header16"

    key = struct.unpack("I", data[0:4])[0]
    header16["key"] = key
    print "key: 0x%x" % key

    crc32 = struct.unpack("I", data[4:8])[0]
    header16["crc32"] = crc32
    print "crc32: 0x%x" % crc32

    decrypted_or_decompressed_len = struct.unpack("I", data[8:12])[0]
    header16["decrypted_or_decompressed_len"] = decrypted_or_decompressed_len 
    print "decrypted_or_decompressed_len: %d" % decrypted_or_decompressed_len

    encrypted_or_compressed_len = struct.unpack("I", data[12:16])[0]
    header16["encrypted_or_compressed_len"] = encrypted_or_compressed_len
    print "encrypted_or_compressed_len: %d" % encrypted_or_compressed_len

    test_crc32 = binascii.crc32(data[8:(8+encrypted_or_compressed_len+8)]) & 0xffffffff
    if test_crc32 != crc32:
        print "bad crc32"
        return

    print "-"*32

    return header16


if __name__ == "__main__":
    fp = open(sys.argv[1], "rb")
    encbuf = fp.read()
    fp.close()

    header16 = decrypt_header16(encbuf[:16])
    header16_encbuf = header16 + encbuf[16:]
    header16 = check_header16(header16_encbuf)

    key1 = "y983nfdicu3j2dcn09wur9*^&(y4r3inf;'fdskaf'SKF"
    key1_loops = 1000

    key1_cp = key1
    while key1_loops:
        md5 = hashlib.new("md5")
        md5.update(key1_cp)
        key1_cp = md5.hexdigest()
        key1_loops -= 1


    rc4 = ARC4.new(key1_cp)
    round1 = rc4.decrypt(encbuf[16:])

    header16b = decrypt_header16(round1[:16])
    header16b_round1 = header16b + round1[16:]
    check_header16(header16b_round1)

    plain = zlib.decompress(str(round1[16:]))
    if not plain.startswith("MZ"):
        print "bad MZ"
        sys.exit(1)

    fp = open(sys.argv[1]+"_plain", "wb")
    fp.write(plain)
    fp.close()
