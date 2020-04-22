def resolve_func_by_hash(func_name):
    hash_val = 0

    for ch in func_name:
        hash_val = ord(ch) + (hash_val << 4)

        math2 = ((hash_val & 0xF0000000) & 0xffffffff)
        if math2 != 0:
            math3 = math2 >> 24
            math4 = hash_val & ~(hash_val ^ 0xfffffff)
            math5 = (~math4 & 0x110BC900)
            hash_val = (~math3 & 0x110BC900 | math3 & 0xEEF436FF) ^ (math5 | (math4 & 0xEEF436FF))

    return hash_val


if __name__ == "__main__":
    func_name = "InternetConnectA"
    func_hash = resolve_func_by_hash(func_name.lower())
    print hex(func_hash)

    #fp = open("lots_of_apis_for_hashing", "rb")
    #lines = fp.readlines()
    #fp.close()

    #for line in lines:
    #    line = line.strip()
    #    func_hash = resolve_func_by_hash(line.lower())

    #    print "0x%x,%s" % (func_hash, line)
