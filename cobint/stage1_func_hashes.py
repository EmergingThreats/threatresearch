def rol(num, count, size):
    return ((num << count) | (num >> (size-count)))


def resolve_func_by_hash(func_name):
    func_hash = 0

    for c in func_name:
        func_hash = (func_hash + ord(c) + rol(func_hash, 8, 32)) & 0xffffffff

    return func_hash 


if __name__ == "__main__":
    func_name = "InternetConnectA"
    func_hash = resolve_func_by_hash(func_name)
    print hex(func_hash)
