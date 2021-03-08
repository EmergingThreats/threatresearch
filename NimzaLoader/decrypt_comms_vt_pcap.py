# sample and pcap from https://www.virustotal.com/gui/file/be498f46b5ebc2f64924853296b4d611b1bf16581d7dbab10b2e9a23edf04c8f/detection

import base64
import json

# pip install pymonocypher
import monocypher


def decrypt_key_material(enc_str1, enc_str2, enc_str3, rounds):
    hash_material = base64.b64decode(enc_str1)
    hash_material_hash = monocypher.blake2b(hash_material)

    nonce = hash_material_hash[0:24]

    hash_material_hash = hash_material
    for i in range(rounds):
        hash_material_hash = monocypher.blake2b(hash_material_hash)

    slice1 = hash_material_hash[:32]
    slice2 = hash_material_hash[32:]

    key = []
    for i, b1 in enumerate(slice1):
        kb = b1 ^ slice2[i]
        key.append(kb)
    key = bytes(key)

    mac = base64.b64decode(enc_str2)

    encbuf = base64.b64decode(enc_str3)

    key_material = monocypher.unlock(key, nonce, mac, encbuf)

    return key_material


def generate_key(key_material, sid_value):
    sid_value_nob64 = base64.b64decode(sid_value)

    # part of the decoded SID value contains a random 16-byte value needed to decrypt the response
    rand_16_bytes = sid_value_nob64[0:16]

    blake = monocypher.Blake2b(key=rand_16_bytes)
    blake.update(key_material)
    hash1 = blake.finalize()

    blake = monocypher.Blake2b(key=hash1)
    blake.update(key_material)
    hash2 = blake.finalize()

    slice1 = hash2[0:32]
    slice2 = hash2[32:]
    key = []
    for i, b1 in enumerate(slice1):
        kb = b1 ^ slice2[i]
        key.append(kb)
    key = bytes(key)

    return key


def decrypt_response(key, response_data):
    response_data_nob64 = base64.b64decode(response_data)

    nonce = response_data_nob64[0:24]
    ciphertext = response_data_nob64[24:-16]
    mac = response_data_nob64[-16:]

    plain_response = monocypher.unlock(key, nonce, mac, ciphertext)

    return plain_response


def generate_JSESSIONID(key):
    blake = monocypher.Blake2b()
    blake.update(key)
    hash1 = blake.finalize()

    slice1 = hash1[0:16]
    slice2 = hash1[16:32]

    buf = []
    for i, b1 in enumerate(slice1):
        kb = b1 ^ slice2[i]
        buf.append(kb)
    buf = bytes(buf)

    JSESSIONID = base64.b64encode(buf)
    print("JSESSIONID: %s" % JSESSIONID)


if __name__ == "__main__":
    # stored as encrypted strings in the binary
    enc_str1 = "f3HpCjtLBMrqlYuj7Hj96g=="
    enc_str2 = "lSoSN/B2kicji7P0Cgv7Cg=="
    enc_str3 = "YyCWR7YX/hUns1YP2yiS9Oims8M7zq2cOFs9wTZw8bQ="
    # changes from sample to sample
    rounds = 126

    # from pcap
    sid_value = "tQS+oDHQCwkaBsX+LGnzsGXebq2IEBbs86rWDC9Nl4rz2y9X9Z4aD8tAnIkp08FIB7bxeWH0s1Kn5oJyb/Cc7GFZLqME/IJyfIRq8E6bggZnSSvWQEO8xqv9poEVx/F1rFOY5dedAJ5Fe71mVxchXtr5UnBRGrYDWSYtwf5j5nGSH233VjJ1jYzpXJJz2Y1ikzal51nEH5I="

    response_data = "Nd3gdcvujq2cxjiWTW/3qpM1u702s86joImztBhTzV2cemIJRonlvcBcWyKPiVRSGQenvzEAJXzUqVTfWNgG0AiJPSAGC7xiI+08ggPjn0w9CEdcQlANhk5Tj6ga9VjTqvkXV7akVgDfuC1P8MWEXBle+W+NfGPuNeyTuEPvDBT0CwBI/yFtf8ztYJXghIn3Inxvv+faq5gSeRXXuUFXI0ZvhWKiQEE6fn7oVPk6ymSroZOi1XEQUG/HZ3G4Rozh4wdaCEcn+LONtHlrQh6wCy4isXASSz3qpSUTtQPmhy/l/9eBmL4Kc7kJsnciFdZIJ1d4NaYqoedLj/yGLvWgbAdoj+ftcjlfELuzgyPNKlqMzVVN+n1VKYvDh87k5uXREKCGt+OZHKIT8jjz"

    key_material = decrypt_key_material(enc_str1, enc_str2, enc_str3, rounds)
    handshake_key = generate_key(key_material, sid_value)

    plain_response = decrypt_response(handshake_key, response_data)

    plain_response_json = json.loads(plain_response)
    print(json.dumps(plain_response_json, indent=4))

    generate_JSESSIONID(handshake_key)
