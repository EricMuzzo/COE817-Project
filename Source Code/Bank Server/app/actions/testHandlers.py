from .handlers import handle_login

testMessage = {
    'ir': '5c8d064ac2fffe35b9fc8e3befd05995',
    'ciphertext': '2c0ff6ca69862df0c1613d3ae7b558232ffdc2382e584dd96f6be84fae75be9da278ebd586de4eadb237d6653e27bcfa'
}

res = handle_login(testMessage)
print(res.ciphertext)