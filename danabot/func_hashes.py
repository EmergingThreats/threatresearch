def resolve_func_by_hash(func_name):
    func_hash = 0

    v2 = len(func_name)
    for l_idx in range(1, len(func_name)+1):
        r_idx = v2 - l_idx
        if v2 == l_idx:
            r_idx = 1

        l_chr = ord(func_name[l_idx-1])
        l_chr_upper = ord(func_name[l_idx-1].upper())
        r_chr = ord(func_name[r_idx-1])
        r_chr_upper = ord(func_name[r_idx-1].upper())

        r_chr ^= v2 
        l_chr_upper ^= v2 
        l_chr ^= v2

        func_hash = ((func_hash + l_chr_upper * r_chr * l_chr) ^ v2 ^ r_chr_upper) & 0xffffffff

    return func_hash


if __name__ == "__main__":
    func_name = "socket"
    func_hash = resolve_func_by_hash(func_name)
    print hex(func_hash)

    #fp = open("lots_of_apis_for_hashing", "rb")
    #lines = fp.readlines()
    #fp.close()

    #for line in lines:
    #    line = line.strip()
    #    func_hash = resolve_func_by_hash(line)

    #    print "0x%x,%s" % (func_hash, line)
