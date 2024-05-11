import hashlib

def hmac(key, message):
    ipad = b'\x36' * 64
    opad = b'\x5c' * 64
    key = key.encode('utf-8')
    message = message.encode('utf-8')

    ipad_key = bytes([x ^ y for x, y in zip(ipad, key)])
    opad_key = bytes([x ^ y for x, y in zip(opad, key)])

    ipad_message = bytes([x ^ y for x, y in zip(ipad_key, message)])
    opad_message = bytes([x ^ y for x, y in zip(opad_key, message)])

    ipad_hash = hashlib.sha256(ipad_message).digest()
    opad_hash = hashlib.sha256(opad_message).digest()

    return hashlib.sha256(opad_hash + ipad_hash).digest()

key = 'my_secret_key'
message = 'Hello, World!'
hmac_value = hmac(key, message)

print(hmac_value.hex())
