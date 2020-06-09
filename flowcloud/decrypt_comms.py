import binascii
import hashlib
import struct
import zlib

from Crypto.Cipher import ARC4


def ror(num, count, size):
    return ((num >> count) | (num << (size-count)))


def decrypt_header28(header):
    outbuf = []

    key = struct.unpack("I", header[0:4])[0]
    outbuf.append(header[0:4])

    for i in range(4, 28):
        pb = (ord(header[i]) ^ ror(key, i, 32)) & 0xff
        outbuf.append(chr(pb))

    header = "".join(outbuf)

    return header


def parse_header28(data):
    print "header28"

    header28 = {}

    key = struct.unpack("I", data[0:4])[0]
    header28["key"] = key
    print "key: 0x%x" % key

    crc32 = struct.unpack("I", data[4:8])[0]
    header28["crc32"] = crc32
    print "crc32: 0x%x" % crc32

    test_crc32 = binascii.crc32(data[8:8+20]) & 0xffffffff
    if test_crc32 != crc32:
        print "bad header28 crc32"
        return

    magic = data[8:12][::-1]
    header28["magic"] = magic
    print "magic: %s" % magic

    counter = struct.unpack("I", data[12:16])[0]
    header28["counter"] = counter
    print "counter: %d" % counter

    unk1 = struct.unpack("I", data[16:20])[0]
    header28["unk1"] = unk1
    print "unknown1: %d" % unk1

    data_len = struct.unpack("I", data[20:24])[0]
    header28["data_len"] = data_len
    print "data length: %d" % data_len

    unk2 = struct.unpack("B", data[24])[0]
    header28["unk2"] = unk2
    print "unknown2: %d" % unk2

    hash_type = struct.unpack("B", data[25])[0]
    header28["hash_type"] = hash_type
    print "hash type: %d" % hash_type

    compression_type = struct.unpack("B", data[26])[0]
    header28["compression_type"] = compression_type
    print "compression type: %d" % compression_type

    crypto_type = struct.unpack("B", data[27])[0]
    header28["crypto_type"] = crypto_type
    print "crypto type: %d" % crypto_type

    return header28


def decrypt_header24(header):
    outbuf = []

    key = struct.unpack("I", header[0:4])[0]
    outbuf.append(header[0:4])

    for i in range(4, 24):
        pb = (ord(header[i]) ^ ror(key, i, 32)) & 0xff
        outbuf.append(chr(pb))

    header = "".join(outbuf)

    return header


def parse_header24(data):
    print "header24"
    header24 = {}

    key = struct.unpack("I", data[0:4])[0]
    header24["key"] = key
    print "key: 0x%x" % key

    crc32 = struct.unpack("I", data[4:8])[0]
    header24["crc32"] = crc32
    print "crc32: 0x%x" % crc32

    magic = data[8:12][::-1]
    header24["magic"] = magic
    print "magic: %s" % magic

    command = struct.unpack("I", data[12:16])[0]
    header24["command"] = command
    print "command: %d" % command

    subcommand = struct.unpack("I", data[16:20])[0]
    header24["subcommand"] = subcommand
    print "subcommand: %d" % subcommand

    data_len = struct.unpack("I", data[20:24])[0]
    header24["data_len"] = data_len
    print "data length: %d" % data_len

    test_crc32 = binascii.crc32(data[8:(8+data_len+16)]) & 0xffffffff
    if test_crc32 != crc32:
        print "bad header24 crc32"
        return

    return header24


def decrypt_header16(header):
    outbuf = []

    key = struct.unpack("I", header[0:4])[0]
    outbuf.append(header[0:4])

    for i in range(4, 16):
        pb = (ord(header[i]) ^ ror(key, i, 32)) & 0xff
        outbuf.append(chr(pb))

    header = "".join(outbuf)

    return header


def parse_header16(data):
    print "header16"
    header16 = {}

    key = struct.unpack("I", data[0:4])[0]
    header16["key"] = key
    print "key: 0x%x" % key

    crc32 = struct.unpack("I", data[4:8])[0]
    header16["crc32"] = crc32
    print "crc32: 0x%x" % crc32

    decrypted_or_decompressed_len = struct.unpack("I", data[8:12])[0]
    header16["decrypted_or_decompressed_len"] = decrypted_or_decompressed_len
    print "decrypted or decompressed length: %d" % decrypted_or_decompressed_len

    encrypted_or_compressed_len = struct.unpack("I", data[12:16])[0]
    header16["encrypted_or_compressed_len"] = encrypted_or_compressed_len
    print "encrypted or compressed length: %d" % encrypted_or_compressed_len

    test_crc32 = binascii.crc32(data[8:(8+encrypted_or_compressed_len+8)]) & 0xffffffff
    if test_crc32 != crc32:
        print "bad header16 crc32"
        return

    return header16


def decrypt_command_data(encbuf):
    key1 = "01a3353484b6e0eb7c8cd8f47ce156104b95d63bbc019c0eb2b5fd922d29043974010ad2301645bc0c66fc122a04590a873601fa1f65f104e37c61635edf718607a493bc379df8bb38f847ca4af10b41bae514375d42b897ef95aa674eccdcef03d41db083b4ed37b3cf36cafee75c7f22165f2673c880b438789783f0b4181d15acf6dea152d63313c94aaf0eb181485a8ab4f47db9a175856ee98edef03d664c9b736cc1052d67509a868c6133744e665ce7c0416e342e8115e9d4546d255b9ee3eb73b9eeabbe48caf3640761717b2cf8549c23519763bd5e61962fa9703f629cbb7f01c25358bc3620b4b1487a6a7720569130e1eccfab901f88f43a0107562f4112b64c6909d28c1c6a3584556d7467501895321cdea444f551cd47fe5e99dce0211ae6f3571451fae58cc909093636a7a0a7eb4db3e2673c0e048d54a2313603948f85407f6fdcd6fed65de3f4344bc68edc4870a306bccbce895db16883a291c9222c5ef033d9cb00d49a779dc8369ab7cf9737b711d98596701b8874dfdd7e117df422ce96487a256bee19a3b0db94673f3d962deb27c95e72bd124275743cb0f18b2471b3fc862226dbe0dc90752bdc8eae4975e1e40112e9d34800584b416175344062061f1a1cb2f8accf6c10d6cb447aceb722a21591d77be91002990b50204117e2f0aae1ade1701eb9310b965a8bbc674c404773305e6a7b88cc68191eaf9d0c66396e0de4aa80198bab1deaa4b22a1b41330c11b647e6c2357a16ed5f04464794860fd1c2a6fa47e98d4dd938ad8a3256587f63e1fd504b93afd7119da2cc3648e884e7be14c595ad6ff86d989238bb836c02e460921464d6f4329056b5560790509a8cc0545db6e1ca51333d9d220a71934a9357383921643502f9f9879ab03392f080a96d4d9d48fc5bbc112bcc337dd662f4ddc7d5d8d7c2f3e0ec0be86824e8f987490a3905d4c96e9ff241cf11b79fa70c803c95a780500bdd0ad3a1ab137000e9e67656e8b0d638f53583d342e8be4c66be353be95ef7208b1d1cba3adb2b1df5bba5f00c372fb9db21bf1ba787e655118d7799452ab35c8ae6bebc9994fd41fb752ee472fa41c7f46fe2776943ae9d9e54eb99a04de63efe9d3fc41083b3b0cfb748a6e43e5e8be5cf0150ef7d93d1a6ee1cb6a5e754990f6941842a24f602ca97533bf0fa3d0058e4d0a06a497374c32eb902454aa494e7e68cc2b9a65b22c89ecfbde75d79f7fa47ac784bf2125b9355989e32fbe32ab7a81055516e56d12bcb655c5f4510177d8114fac77617ae3a1cae46e2388228b231db2cc812bfa25790dcd7af4864569790295f5a860d6fdc301a44126bd5b391fc24c83dded6fc34d2a308762ebb8201e9b3efc08664eb27301af840bb15418e75433e0ed2bb1eaf6cccd695f3423cf8731e8cfd93ef4cc6301259307b".decode("hex")

    key1_loops = 1
    key1_cp = key1
    while key1_loops:
        md5 = hashlib.new("md5")
        md5.update(key1_cp)
        key1_cp = md5.hexdigest()
        key1_loops -= 1

    rc4 = ARC4.new(key1_cp)
    decrypted_buf = rc4.decrypt(encbuf)

    return decrypted_buf


def decrypt_data(data):
    i = 0
    while i < len(data):
        enc_header28 = data[i:i+28]
        i += 28

        if len(enc_header28) != 28:
            print "bad enc_header28 length"
            break

        header28 = decrypt_header28(enc_header28)
        parsed_header28 = parse_header28(header28)
        print

        enc_header24 = data[i:i+24]
        i += 24
        if len(enc_header24) != 24:
            print "bad enc_header24 length"
            break

        header24 = decrypt_header24(enc_header24)
        parsed_header24 = parse_header24(header24 + data[i:i+parsed_header28["data_len"]])
        print

        if parsed_header24["data_len"] > 0:
            inner_data = data[i:i+parsed_header24["data_len"]]
            i += parsed_header24["data_len"]

            enc_header16 = inner_data[0:16]
            header16 = decrypt_header16(enc_header16)
            parsed_header16 = parse_header16(header16 + inner_data[16:])
            print

            enc_command_data = inner_data[16:16+parsed_header16["encrypted_or_compressed_len"]]
            compressed_command_data = decrypt_command_data(enc_command_data)

            enc_header16b = compressed_command_data[0:16]
            header16b = decrypt_header16(enc_header16b)
            parsed_header16b = parse_header16(header16b + compressed_command_data[16:])
            print
            if parsed_header16b:
                command_data = zlib.decompress(compressed_command_data[16:])

                print "command data: %s" % repr(command_data)
                import pdb; pdb.set_trace()

        print "*"*64

        
if __name__ == "__main__":
    data = "hex encoded data here".decode("hex")

    decrypt_data(data)
