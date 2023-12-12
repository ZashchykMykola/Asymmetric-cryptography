import math
import random

def binToDec(string):
    result = int(string, 2)
    return result

def generatorBBS(array, length, r0):
    p = 284100283511244958272321698211826428679
    q = 22582480853028265529707582510375286184991
    ri = r0
    for i in range(length):
        rii = pow(ri, 2, p*q)
        if(rii % 2 == 0):
            array.append(0)
        if(rii % 2 != 0):
            array.append(1)
        ri = rii

def MillerRabin(p):
    k = 15
    d, s = findDS(p - 1)
    counter = 0
    flag = 0
    while(counter <= k):

        x = random.randrange(2, p - 1)

        gcdxp = math.gcd(x, p)
        if (gcdxp > 1):  # step 1
            return 0
        else:
            if (gcdxp == 1):
                test = pow(x, d, p)
                if(test == 1 or test - p == -1):  # step 2.1
                    flag = 1
                else:
                    for r in range(1, s + 1):
                        t = d * pow(2, r)
                        xr = pow(x, t, p)  # step 2.2
                        if (xr - p == -1):
                            flag = 1
                        else:
                            if (xr - p == 1):
                                flag = 0


        if (flag == 0):
            return 0    # step 2.3
        else:
            if(counter == k and flag == 1):
                return 1
            counter = counter + 1   # step 3

def findDS(p):
    s = 0
    d = p
    while (True):
        if (d % 2 == 1):
            break
        if (d % 2 == 0):
            s = s + 1
            d = int(d / 2)

    return d, s


first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)


def getLowLevelPrime(n):
    while True:
        pc = nBitRandom(n)

        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor ** 2 <= pc:
                break
        else:
            return pc

def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc - 1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert (2 ** maxDivisionsByTwo * ec == mrc - 1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2 ** i * ec, mrc) == mrc - 1:
                return False
        return True

    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True


# number_bin = []
# generatorBBS(number_bin, 128, 244958272321698211826428679)
#
# number_dec_string = ""
# for i in range(len(number_bin)):
#     number_dec_string = number_dec_string + str(number_bin[i])
#
# number_dec = binToDec(number_dec_string)
# print("Generated number:", number_dec)
#
# a = MillerRabin(328886635085015787363279211084797614599)
# print(a)





#print(n1, n2)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def GenerateKeyPair(p, q):
    n = p * q
    phi_n = (p - 1)*(q - 1)
    e = pow(2, 16) + 1

    # while(True):
    #     if(math.gcd(e1, phi_n1) == 1):
    #         break
    #     else:
    #         e1 = random.randrange(2, phi_n1 - 1)

    keyV = []
    keyV.append(n)
    keyV.append(e)

    d = modinv(e, phi_n)

    return keyV, d


def Encrypt(M, keyV):
    n = keyV[0]
    e = keyV[1]

    C = pow(M, e, n)
    return C


def Decrypt(C, d, keyV):
    n = keyV[0]
    M = pow(C, d, n)
    return M


def Sign(M, d,keyV):
    n = keyV[0]
    S = pow(M, d, n)

    signed = []
    signed.append(M)
    signed.append(S)
    return signed


def Verify(signedM, keyV):
    n = keyV[0]
    e = keyV[1]
    M = signedM[0]
    S = signedM[1]

    if(M == pow(S, e, n)):
        return "Verified"
    else:
        return "Not verified"


def SendKey(keyV, keyP, keyV2):
    e = keyV[1]
    n = keyV[0]
    e1 = keyV2[1]
    n1 = keyV2[0]
    d = keyP
    k = random.randrange(1, n-1)
    if(n1 < n):
        return "Choose another pair!"
    else:
        k1 = pow(k, e1, n1)
        S = pow(k, d, n)
        S1 = pow(S, e1, n1)
    message = []
    message.append(k1)
    message.append(S1)

    return message


def ReceiveKey(message, keyV, keyV2, keyP2):
    e = keyV[1]
    n = keyV[0]
    d1 = keyP2
    n1 = keyV2[0]
    k1 = message[0]
    S1 = message[1]

    k = pow(k1, d1, n1)
    S = pow(S1, d1, n1)

    received_message = []
    received_message.append(k)
    received_message.append(S)

    if(k == pow(S, e, n)):
        state = "Verified"
        return received_message, state
    else:
        state = "Not verified"
        return received_message, state


array_of_primes = []

while len(array_of_primes) != 4:
        n = 128
        prime_candidate = getLowLevelPrime(n)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            array_of_primes.append(prime_candidate)

#print("Generated prime numbers: ", array_of_primes, "\n")

array_of_primes = [228082965183251874217606288893283930369, 207444809325450376075231297849696891607, 253821941242440288348445457833098880579, 326781925554111869458305036329632488713]
p1 = array_of_primes[0]
p2 = array_of_primes[1]
q1 = array_of_primes[2]
q2 = array_of_primes[3]

M = 0xabcdef

keyV, keyP = GenerateKeyPair(p1, q1)
print("Key public: ", keyV)
print("Key public HEX: ", hex(keyV[0]))
print("Secret key HEX: ", hex(keyP))

server_key = [0x8F5BC9E981A756349B90CF96D3880DEF2DC8B3348D03F2BC5AA5A0ACD9909861, 0x10001]

eM = Encrypt(M, server_key)

print("Encrypted message HEX:", hex(eM))


server_eM = 0x6EE0599A5B1D75C9697618DC225D3B6870BBB67F84AB67472471A851C302A90E

newM = Decrypt(server_eM, keyP, keyV)

print("Decrypted message:", hex(newM))

M_to_verify = 0x1234567890

signedM = Sign(M, keyP, keyV)
print("Signed message: ", hex(signedM[0]))
print("Signature HEX", hex(signedM[1]))

server_message_to_verify = [0xabcdef, 0x162FDC9FEE71188F392AF012FF5BAAE139D728B9EC1C713AF6D00B7E74807EFB]
print("State:", Verify(server_message_to_verify, server_key))

key_message_from_server = [0x39B6DC92556BB44674BFFC7C3AFE9D664603158B6F53D26029B067DAA4EC27CA, 0x0CE9B136658A48A5]
print("State:", Verify(key_message_from_server, server_key))

#key_to_send, newD = GenerateKeyPair(p2, q2)

my_message = SendKey(keyV, keyP, server_key)
print(my_message)
print("Key:", hex(my_message[0]))
print("Signature:", hex(my_message[1]))

