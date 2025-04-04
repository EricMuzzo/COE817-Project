import helpers

key = helpers.fetch_key()
print(key)

data = {
    "type": "login",
    "data": {
        "name": "Eric"
    }
}

encrypted = helpers.encrypt_with_key(data, key)
print(encrypted)

# original = helpers.decrypt_with_key(encrypted, key)
# print(original)