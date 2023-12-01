from hashlib import sha512 as SHA_512
import random
import hmac

# control parameters
block_size = 128
# ipad and opad
opad = bytes((x ^ 0x5C) for x in range(256))
ipad = bytes((x ^ 0x36) for x in range(256))
# test message
message = "This input string is being used to test my own implementation of HMAC-SHA-512."
# key size in bits
key_size = 128
# key (randomly generated)
key = random.randbytes(key_size // 8)

# HMAC-SHA-512 implementation
def HMAC_SHA512(key, msg, hash_func):
    # convert message to bytes if it is not already
    if type(msg) != bytes:
        msg = msg.encode()
    
    # create inner and outer hash functions
    outer = hash_func()
    inner = hash_func()

    # If key is longer than block_size, hash it
    if len(key) > block_size:
        key = hash_func(key).digest()

    # if key is shorter than block size, pad it with zeros
    # ljust: left justify the string with zeros
    key = key.ljust(block_size, b'\0')

    # XOR key with ipad and opad
    # translate: translate bytes according to a mapping table (opad or ipad)
    outer.update(key.translate(opad))
    inner.update(key.translate(ipad))
    
    # hash key XOR ipad concatenated with message
    inner.update(msg)
    # hash key XOR opad concatenated with hash of key XOR ipad concatenated with message
    outer.update(inner.digest())

    # Return hexdigest of outer hash
    return outer.hexdigest()

# Results
print("Message: ", message)
print("Key: ", key.hex())
hexdigest1 = HMAC_SHA512(key, message.encode(), SHA_512)
print("\nHMAC-SHA-512 (my implementation): ", hexdigest1)
hexdigest2 = hmac.new(key, message.encode(), SHA_512).hexdigest()
print("\nHMAC-SHA-512 (hmac library): ", hexdigest2)

# check if our implementation matches the hmac library
if hexdigest1 == hexdigest2:
    print("\nOur implementation matches the hmac library.")
else:
    print("\nOur implementation does not match the hmac library.")
