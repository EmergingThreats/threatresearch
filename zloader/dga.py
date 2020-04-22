import calendar
import datetime
import struct

from Crypto.Cipher import ARC4


def get_dga_domains(dt, rc4_key, num_domains):
    time = calendar.timegm(dt.timetuple())
    time_str = struct.pack("I", time)

    rc4 = ARC4.new(rc4_key)
    seed_str = rc4.encrypt(time_str)
    seed = struct.unpack("I", seed_str)[0]

    v1 = seed
    domains = []
    for i in range(num_domains):
        domain = []
        for i in range(20):
            next_chr = v1 % 25 + ord("a")
            domain.append(chr(next_chr))

            v7 = next_chr + v1
            v1 = seed ^ v7

        # .com stored as encrypted string
        domain = "".join(domain) + ".com"
        domains.append(domain)

    return domains


if __name__ == "__main__":
    # 2b5e50bc3077610128051bc3e657c3f0e331fb8fed2559c6596911890ea866ba
    rc4_key = "41997b4a729e1a0175208305170752dd"

    dt = datetime.datetime(2020, 04, 8)
    num_domains = 32

    dga_domains = get_dga_domains(dt, rc4_key, num_domains)
    for dga_domain in dga_domains:
        print dga_domain
