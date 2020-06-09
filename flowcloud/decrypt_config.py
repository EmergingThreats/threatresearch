import sys


if __name__ == "__main__":
    fp = open(sys.argv[1], "rb")
    encbuf = fp.read()
    fp.close()

    plainbuf = []
    for eb in encbuf:
        pb = (ord(eb) ^ 0x29) + 0x29
        plainbuf.append(chr(pb & 0xff))

    plainbuf = "".join(plainbuf)
    
    fp = open(sys.argv[1]+"_plain", "wb")
    fp.write(plainbuf)
    fp.close()
