def resolve_func_by_hash(func_name, xor_key):
    func_hash = 0

    for ch in func_name:
        func_hash = ((ord(ch) ^ xor_key) + ((func_hash << 7) | (func_hash >> 25))) & 0xffffffff

    return func_hash


if __name__ == "__main__":
    func_name = "lstrlenA"
    func_hash = resolve_func_by_hash(func_name, 0x5)
    print "0x%x: %s" % (func_hash, func_name)
