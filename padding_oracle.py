
from base64 import b64encode, b64decode
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from util import pkcs7_pad, createRandomBlock

class PaddingOracle:

    def __init__(self, blocksize=8):
        self.blocksize = blocksize

    def isValidPadding(self, dataBytes):
        raise NotImplementedError

    def encrypt(self, plainText):
        blockCount = int(len(plainText) / self.blocksize) + 1
        # pad plaintext
        plainTextBytes = bytearray(pkcs7_pad(plainText, self.blocksize).encode('utf-8'))

        # generate random block
        last_block = createRandomBlock(self.blocksize)

        result = last_block
        for blockIndex in reversed(range(0, blockCount)):
            startByte = (blockIndex * self.blocksize)
            endByte = startByte + self.blocksize
            currentBlock = plainTextBytes[startByte:endByte]
            last_block = self.encryptBlock(currentBlock, last_block)
            result = last_block + result
        return result

    def encryptBlock(self, block, nextBlock):
        result = bytearray(self.blocksize)

        for index in reversed(range(0, self.blocksize)):
            result[index] = self.find_byte_to_encrypt(index, result, nextBlock)

        for i in range(0, self.blocksize):
            result[i] = result[i] ^ block[i]

        return result

    def find_byte_to_encrypt(self, index, result, nextBlock):
        if len(nextBlock) != self.blocksize:
            raise Exception('Block is the wrong size!')

        paddingByte = self.blocksize - index
        block = bytearray(self.blocksize)
        for i in range(index, self.blocksize):
            block[i] = paddingByte ^ result[i]

        pool = ThreadPoolExecutor(50)
        paddingCheckTasksMap = {}
        paddingCheckTasksList = []
        for byteValue in reversed(range(0, 256)):
            block[index] = paddingByte ^ nextBlock[index] ^ byteValue
            blockToCheck = block + nextBlock
            future = pool.submit(self.isValidPadding, blockToCheck.copy())
            paddingCheckTasksList.append(future)
            paddingCheckTasksMap[id(future)] = block.copy()
            #if self.isValidPadding(blockToCheck):
            #    print('Valid:' + str(byteValue))
            #    return block[index] ^ paddingByte

        for future in as_completed(paddingCheckTasksList):
            if future.result() == True:
                validBlock = paddingCheckTasksMap[id(future)]

                # cancel other tasks
                for futuresToCancel in paddingCheckTasksList:
                    futuresToCancel.cancel()
                paddingCheckTasksList.clear()
                paddingCheckTasksMap.clear()

                return validBlock[index] ^ paddingByte

        raise Exception('Couldn\'t find a valid encoding!')

    def decrypt(self, cipherTextBase64):
        cipherBytes = b64decode(cipherTextBase64)
        blockCount = int(len(cipherBytes) / self.blocksize)
        plaintextBytes = bytearray(0)
        for blockIndex in reversed(range(0, blockCount)):
            if (blockIndex == 0):
                break
            # try to decrypt
            plaintextBytes = self.decryptBlock(blockIndex, cipherBytes) + plaintextBytes
            print(plaintextBytes)
        return plaintextBytes

    def decryptBlock(self, blockIndex, cipherBytes):
        startByte = (blockIndex * self.blocksize)
        endByte = startByte + self.blocksize
        # get the block to decrypt
        blockToDecrypt = cipherBytes[startByte:endByte]
        previousCipherBlock = cipherBytes[(startByte - self.blocksize):(endByte - self.blocksize)]
        # initialy filled with zero
        cipherBlock = bytearray(self.blocksize)
        # create block to send to the oracle
        cipherBlock.extend(blockToDecrypt)
        plaintextBlockBytes = bytearray(self.blocksize)

        pool = ThreadPoolExecutor(50)
        paddingCheckTasksMap = {}
        paddingCheckTasksList = []
        for blockByteIndex in reversed(range(0, self.blocksize)):
            paddingByte = self.blocksize - blockByteIndex

            # check this parallel
            for byteValue in reversed(range(0, 256)):
                cipherBlock[blockByteIndex] = byteValue
                future = pool.submit(self.isValidPadding, cipherBlock.copy())
                paddingCheckTasksList.append(future)
                paddingCheckTasksMap[id(future)] = byteValue

            for future in as_completed(paddingCheckTasksList):
                if future.result() == True:
                    validByteValue = paddingCheckTasksMap[id(future)]
                    # cancel other tasks
                    for futuresToCancel in paddingCheckTasksList:
                        futuresToCancel.cancel()
                    paddingCheckTasksList.clear()
                    paddingCheckTasksMap.clear()
                    # calculate plaintext byte
                    cipherBlock[blockByteIndex] = validByteValue
                    plaintextBlockBytes[blockByteIndex] = paddingByte ^ cipherBlock[blockByteIndex] ^ previousCipherBlock[blockByteIndex]
                    # prepare next bytes
                    for nextPadIndex in range(blockByteIndex, self.blocksize):
                        cipherBlock[nextPadIndex] = (paddingByte + 1) ^ plaintextBlockBytes[nextPadIndex] ^ previousCipherBlock[nextPadIndex]
                    break
        return plaintextBlockBytes
