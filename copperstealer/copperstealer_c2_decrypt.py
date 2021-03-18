import base64
import binascii
import sys
from Crypto.Cipher import DES


def modified_b64(encbuf):
    my_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    r1 = encbuf.replace("~", "=")
    r2 = r1.translate(str.maketrans(my_base64chars, std_base64chars))

    plain = base64.b64decode(r2)

    return plain


def decrypt(encbuf, key, iv):
    r1 = modified_b64(encbuf)

    des = DES.new(key.encode(), DES.MODE_CBC, iv.encode())
    try:
        r2 = des.decrypt(r1)
    except ValueError:
        return None
    else:
        return r2.decode('utf-8', 'backslashreplace')


if __name__ == "__main__":
    encbuf = sys.argv[1]

    keys = [
        ('taskhost', 'winlogon'),
        ('rundll32', 'explorer'),
        ('loadfaid', 'unsigned')
    ]

    for key_iv in keys:
        try:
            decbuf = decrypt(encbuf, key_iv[0], key_iv[1])
        except binascii.Error:
            print(f"input does not seem encrypted {encbuf}")
            exit()
        else:
            # if the encbuf couldn't be decrypted
            if decbuf is None:
                continue

            if decbuf.startswith('[') or decbuf.startswith('own=') or 'guid=' in decbuf:
                # found a valid cleartext
                print(f"Encrypted: {encbuf}\nDecrypted: {decbuf}\nKey and IV: {key_iv}")
                exit()
            elif decbuf.encode('utf-8', 'backslashreplace') == b'\x08\x08\x08\x08\x08\x08\x08\x08':
                # found an empty buffer
                print(f"Encrypted:  {encbuf}\nDecrypted: {decbuf.encode('utf-8', 'backslashreplace')}\nKey and IV: {key_iv}")
                exit()
            else:
                continue

    print("Unable to decrypt with known keys")
