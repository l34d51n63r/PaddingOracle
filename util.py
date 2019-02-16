import random

def pkcs7_pad(text, blocksize):
    length = blocksize - (len(text) % blocksize)
    text += chr(length) * length
    return text

def createRandomBlock(blocksize):
    block = bytearray(blocksize)
    for i in range(0, blocksize):
        block[i] = random.randint(0, 255)
    return block
