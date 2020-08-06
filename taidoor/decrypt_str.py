# A slightly better string decryption Python snippet than the one shared in Malware Analysis Report (AR20-216A)
# Hacked together from IDA/Hexrays output


def decrypt(key, encbuf):
    S = ksa(key)

    plainbuf = []
    for i in range(0, len(encbuf)/2):
        S, pb = prng(S, ((ord(encbuf[2 * i + 1]) + 0x80) | (16 * (ord(encbuf[2 * i]) + 0x80))) & 0xff)

        if i > 0:
            plainbuf.append(chr(pb))

    plainbuf = "".join(plainbuf)

    return plainbuf


def prng(S, a2):
    S = prng_transform(S)

    #v3 = (a2 ^ (S[(S[S[256]] + S[S[257]]) % 0xff] ^ S[S[(S[S[259]] + S[S[260]] + S[S[258]]) & 0xff]]) & 0xff) & 0xff
    eax = S[258]
    ecx = S[eax]
    eax = S[260]
    eax = S[eax]
    edx = S[257]
    edx = S[edx]
    edi = S[256]
    edi = S[edi]
    ecx = (ecx + eax) & 0xffffffff
    eax = S[259]
    eax = S[eax]
    ecx = (ecx + eax) & 0xffffffff
    eax = 0xff
    ecx = ecx & eax
    ecx = S[ecx]
    cl = S[ecx]
    edx = (edx + edi) & 0xffffffff
    edx = edx & eax
    cl = (cl ^ S[edx]) & 0xff
    al = a2 & 0xff
    cl = (cl ^ al) & 0xff

    S[260] = al
    S[259] = cl

    return S, cl


def prng_transform(S):
    v1 = S[256]
    v2 = S[260]
    v3 = S[v2]
    S[257] = (S[257] + S[v1]) & 0xff
    S[256] = (v1 + 1) & 0xff
    S[v2] = S[S[257]]
    S[S[257]] = S[S[259]]
    S[S[259]] = S[S[256]]
    S[S[256]] = v3
    result = S[v3]
    S[258] = (S[258] + result) & 0xff

    return S


def ksa_transform(S, a2, key, a5, a6):
    v7 = 0

    i = 1
    while i < a2:
        i = 2 * i + 1

    while True:
        a5 = (ord(key[a6]) + S[a5]) & 0xff
        a6 += 1
        if a6 >= len(key):
            a6 = 0
            a5 = (a5 + len(key)) & 0xff

        result = i & a5
        v7 += 1
        if v7 > 11:
            result %= a2

        if result <= a2:
            break

    return result, a5, a6


def ksa(key):
    S = []
    for i in range(256):
        S.append(i)

    v9 = 0
    v10 = 0
    v5 = 255

    while True:
        v6, v10, v9 = ksa_transform(S, v5, key, v10, v9)
        v7 = S[v5]
        S[v5] = S[v6]
        v5 -= 1
        S[v6] = v7

        if not v5:
            break

    S.append(S[1])
    S.append(S[3])
    S.append(S[5])
    S.append(S[7])
    S.append(S[v10])

    return S


if __name__ == "__main__":
    key = '\x194\xf4\xd2\xe9\xb3\x0f'

    # some examples
    #encbuf = '\x81\x81\x81\x84\x8f\x85\x83\x85\x81\x8f\x88\x8c\x89\x8b\x81\x8b\x8a\x84\x87\x81\x89\x88\x84\x80\x88\x8b'

    encbuf = '\x88\x8e\x88\x8f\x83\x8a\x8d\x80\x82\x81\x8c\x8c\x89\x8f\x88\x82\x8f\x8c\x80\x83\x89\x85\x8f\x8c\x8a\x89\x87\x8a\x84\x8e\x8f\x81'

    plainbuf = decrypt(key, encbuf)
    print(plainbuf)
