'''                  PART 1  S-DES  Elias Ennebt 18391679                 '''
'''-----------------------------------------------------------------------'''

# FIXED PERMUTATIONS
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6) # PERMUTATION 10 REORDER 10 BITS
P8 = (6, 3, 7, 4, 8, 5, 10, 9) # PERMUTATION 8 REORDER 8 BITS
P4 = (2, 4, 3, 1) # 4 Bit Permutation

IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_inverse = (4, 1, 3, 5, 7, 2, 8, 6) # IP INVERSE

EP = (4, 1, 2, 3, 2, 3, 4, 1) # EXPONENTIAL PERMUTATION

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],  # S0 Function
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3], # S1 Function
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


# GetInput  8 BIT PLAINTEXT OR CIPHERTEXT
def getInput():
    while(True):
        # PlainText 8 bits long and 0's and 1's
        plaintext = input("Enter an 8-bit plaintext: ")
        if(len(plaintext) == 8):
            # Length of Bit String
            bitstringlen = 0
            for c in plaintext:
                if(c == "0" or c == "1"):
                    # Bitstringlen == 8 return plaintext
                    bitstringlen += 1
            if(bitstringlen == len(plaintext)):
                break
            else:
                # Bitsring must contain 0's or 1's
                print("ERROR: bitstring can only contain 0's and 1's")
        else:
            # if not bitstring must be 8 bits long
            print("ERROR: Bitstring must by 8 Bits long  ")

    return plaintext

#10 bit key
def getKey():
    while(True):
        # 10 bit key input length must be 10
        key = input("Enter a 10-bit key: ")
        if(len(key) == 10):
            bitkeyLen = 0    # Length of 10 bit Key
            for c in key:
                if(c == "0" or c == "1"):
                    bitkeyLen += 1
                    # bitstringlen == 10 return plaintext
            if(bitkeyLen == len(key)):
                break
            else:
                # Bitsring must contain 0's or 1's
                print("bitstring can only contain 0's and 1's")
        else:
            # if not bitstring must be 10 bits long
            print("Wrong number of bits. Try Again Must be 10 bits!")

    return key

# Permutation Function
def permutate(originalKey, Permutate):
    result = ''
    for i in Permutate:
        result += originalKey[i - 1]
    return result

# Left Bit string
def leftHalfBits(key):
    # Left Bits
    return key[:len(key) // 2]

# Right Bit string
def rightHalfBits(key):
    # Right Bits
    return key[len(key) // 2:]


def shifting(Key):  # performs the shifting
    # Shift Bits to Left by 1
    LeftRotated = leftHalfBits(Key)[1:] + leftHalfBits(Key)[0]
    # Shift Bits to Right
    RightRotated = rightHalfBits(Key)[1:] + rightHalfBits(Key)[0]
    return LeftRotated + RightRotated

# Permutate Key1
def key1(key):
    # Key1 permutation
    return permutate(shifting(permutate(key, P10)), P8)

# Permutate Key2
def key2(key):
    # Key2 permutation
    return permutate(shifting(shifting(shifting(permutate(key, P10)))), P8)


def XOR(text, key):
    Xor_result = ''
    for bit, keyBit in zip(text, key):
        Xor_result += str(((int(bit) + int(keyBit)) % 2))
    return Xor_result

# DEF function SBOX
def sbox(inputBits, sbox):
    # convert in base 2 Row
    row = int(inputBits[0] + inputBits[3], 2)
    # column convert in base 2
    column = int(inputBits[1] + inputBits[2], 2)
    # return the number in base 10
    return '{0:02b}'.format(sbox[row][column])


def fk(bits, key):
    # Left Bits
    Left = leftHalfBits(bits)
    # Right Bits
    Right = rightHalfBits(bits)
    bitperm = permutate(Right, EP)
    # Xored = xor Bits
    Xor_results = XOR(bitperm, key)
    # SBOXresults = xor Bits
    Sbox_results = sbox(leftHalfBits(Xor_results), S0) + sbox(rightHalfBits(Xor_results), S1)
    # Results permutation
    results = permutate(Sbox_results, P4)
    return XOR(results, Left)




# Encryption Algorithm
def encrypt(plainText, keyyer1, keyyer2):
    print("Encrypting the Plaintext value: " + plainText)

    # Permutate string
    bits = permutate(plainText, IP)
    print("Permmutate: " + str(bits))

    Fresult = fk(bits, keyyer1)
    print("Fresult1: " + str(Fresult))

    bits = rightHalfBits(bits) + Fresult

    Fresult2 = fk(bits, keyyer2)
    print("Fresult2: " + str(Fresult))

    CipherText = permutate(Fresult2 + Fresult, IP_inverse)
    return CipherText


# Decryption Algorithm
def decrypt(cipherText, keyyer1, keyyer2):
    print("Decrypting the  CipherText value: " + cipherText)

    bits = permutate(cipherText, IP)
    print("Permmutate: " + str(bits))

    Fresult = fk(bits, keyyer2)
    print("Fresult1: " + str(Fresult))

    bits = rightHalfBits(bits) + Fresult

    Fresult2 = fk(bits, keyyer1)
    print("Fresult2: " + str(Fresult))


    PlainText = permutate(Fresult2 + Fresult, IP_inverse)
    return PlainText





# MAIN MENU
def menu():
    while (True):
        try:
            print("\nWould you like to "
                "\na. encrypt "
                "\nb. Decrypt"
                "\nc. Exit ")
            # Input Choice
            choice = (input())
            if (choice == "a"):
                # PlainText Input
                PlainText = getInput()
                # 10 Bit Key
                key = getKey()
                # Key 1
                key3 = key1(key)
                # Key 2
                key4 = key2(key)
                # Key
                print("10 Bit Key: " + str(key))
                # Encrypted
                encrypted = encrypt(PlainText, key3, key4)
                # Key 1
                print("\nKey1: " + str(key3))
                # Key 2
                print("Key2: " + str(key4))
                # Encryption
                print("Encrypted CipherText Value is: " + str(encrypted))
            elif (choice == "b"):
                # Plaintext
                PlainText = getInput()
                # 10 Bit Key
                key = getKey()
                # Key 1
                key3 = key1(key)
                # Key 2
                key4 = key2(key)
                print("10 Bit Key: " + str(key))
                # Decryption
                decrypted = decrypt(PlainText, key3, key4)
                # 10 Bit Key

                # Key 1
                print("\nKey1: " + str(key3))
                # Key 2
                print("Key2: " + str(key4))
                # Decrypted Key
                print("Decrypted Plaintext is : " + str(decrypted))
            elif(choice == "c"):
                # Exit
                exit()
                break
            else:
                print("Incorrect try again .. \n")
        except ValueError:
            continue


if __name__ == '__main__':
    menu()


'''-------------------------------------------------------------------------'''
'''                  PART 1  S-DES  Elias Ennebt 18391679                   '''

