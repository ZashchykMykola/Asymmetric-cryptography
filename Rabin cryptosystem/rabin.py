import math
import random

def binToDec(string):
    result = int(string, base=2)
    return result

def decToBin(number):
    binn = bin(number)
    bin_number = binn[2:]
    bin_number = list(bin_number)
    bin_number = list(map(int, bin_number))
    return bin_number

def decToHex(number):
    hexx = hex(number)
    # hex_number = hexx[2:]
    # hex_number = list(hex_number)
    # hex_number = list(map(int, hex_number))
    return hexx

def hexToDec(number):
    intt = int(number, base=16)
    return intt

def arrayToString(array):
    result = ""
    for i in range(len(array)):
        result = result + str(array[i])
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

# def jacobi_symbol(n, k):
#
#     n %= k
#     t = 1
#     while n:
#         while not n % 2:
#             n /= 2
#             r = k % 8
#             if r == 3 or r == 5:
#                 t = -t
#         n, k = k, n
#         if n % 4 == 3 and k % 4 == 3:
#             t = -t
#         n %= k
#     return t if k == 1 else 0

def jacobi_symbol(t, l):
    n = t
    x = l
    k = 0
    m = 1
    while(k != 2 and k != 1 and k != 0):
        while (x % 2 == 0):
            x = x // 2
            k = k + 1
        if (k % 2 != 0):
            if (((n * n - 1) // 8) % 2 == 0):
                m = 1 * m
            else:
                m = -1 * m
        if(x == 2):
            if (((n * n - 1) // 8) % 2 != 0):
                m = m * (-1)
                return m
        if(x == 1):
            return m

        k = n
        n = x
        x = k

        if (((n - 1) * (x - 1) // 4) % 2 != 0):
            m = m * (-1)

        x = x % t

        if (x == 2):
            if (((n * n - 1) // 8) % 2 != 0):
                m = m * (-1)
            return m

        if (x == 1):
            return m

    return -1






def gcdExtended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y

# generating functions

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

# Rabin functions

def checkForm(p):
    if((p - 3) % 4 == 0):
        return 1
    else:
        return 0

def GenerateKeyPair(p, q):
    n = p * q
    secret_key = []
    secret_key.append(p)
    secret_key.append(q)
    return secret_key, n

def GenerateNumberByLength(length, seed):
    number_bin = []
    generatorBBS(number_bin, length, 244958272321698211826428679 + seed)

    number_dec_string = ""
    for i in range(len(number_bin)):
        number_dec_string = number_dec_string + str(number_bin[i])

    number_dec = binToDec(number_dec_string)
    return number_dec

def Formatting(m, seed, n):
    x_bin = []
    m_bin = decToBin(m)
    n_bin = decToBin(n)
    l = len(n_bin)
    m = len(m_bin)
    r_size = 64
    for i in range(8):
        x_bin.append(0)

    for i in range(8):
        x_bin.append(1)

    number_of_zeros = l - (m+r_size+16)
    for i in range(number_of_zeros):
        x_bin.append(0)

    for i in range(m):
        x_bin.append(m_bin[i])

    r = GenerateNumberByLength(r_size, seed)
    r_bin = decToBin(r)

    for i in range(len(r_bin)):
        x_bin.append(r_bin[i])

    formatedM = binToDec(arrayToString(x_bin))

    return formatedM, number_of_zeros

def Unformatting(x, n, number_of_zeros):
    n_bin = decToBin(n)
    l = len(n_bin)
    m_bin = decToBin(x)

    for i in range(64):
        m_bin.pop()

    for i in range(8):
        m_bin.pop(0)

    # for i in range(number_of_zeros):
    #     m_bin.pop(0)

    M = binToDec(arrayToString(m_bin))

    return M

def Encrypt(x, n, b):
    # x - formatted
    y = (x*(x + b)) % n

    inv2 = inversedElement(2, n)
    c1 = (((b * inv2) + x) % n) % 2
    temp_c2 = jacobi_symbol(n, x + (b*inv2))
    if(temp_c2 == 1):
        c2 = 1
    else:
        c2 = 0

    encrypted_message = []
    encrypted_message.append(y)
    encrypted_message.append(int(c1))
    encrypted_message.append(c2)

    return encrypted_message

def Decrypt(encrypted_message, b, secret_key, n):
    # y - formatted

    y = encrypted_message[0]
    c1 = encrypted_message[1]
    c2 = encrypted_message[2]

    p = secret_key[0]
    q = secret_key[1]
    inv2 = pow(2, -1, n)
    print(inv2)
    inv4 = pow(4, -1, n)

    ux = (y+(inv4*b))
    s1, s2, s3, s4 = FindSquareRoots(ux, p, q)

    print(s1, s2, s3, s4, '\n')
    print("n:", n)
    print("((b*inv2)) % n:", ((b*inv2)) % n)

    s1 = s1 - ((b*inv2) % n)
    s2 = s2 - ((b * inv2) % n)
    s3 = s3 - ((b * inv2) % n)
    s4 = s4 - ((b * inv2) % n)

    s = [s1, s2, s3, s4]
    s = [i + n if i < 0 else i for i in s]
    print(1111111111111)
    for i in s:
        print(hex(i))



    c1_s1 = (((b * inv2) + s1) % n) % 2
    temp_c2_s1 = jacobi_symbol(s1 + inv2, n)
    if (temp_c2_s1 == 1):
        c2_s1 = 1
    else:
        c2_s1 = 0


    c1_s2 = (((b * inv2) + s2) % n) % 2
    temp_c2_s2 = jacobi_symbol(s2 + inv2, n)
    if (temp_c2_s2 == 1):
        c2_s2 = 1
    else:
        c2_s2 = 0


    c1_s3 = (((b * inv2) + s3) % n) % 2
    temp_c2_s3 = jacobi_symbol(s3 + inv2, n)
    if (temp_c2_s3 == 1):
        c2_s3 = 1
    else:
        c2_s3 = 0


    c1_s4 = (((b * inv2) + s4) % n) % 2
    temp_c2_s4 = jacobi_symbol(s4 + inv2, n)
    if (temp_c2_s4 == 1):
        c2_s4 = 1
    else:
        c2_s4 = 0


    if(c1_s1 == c1 and c2_s1 == c2):
        return s1
    else:
        if (c1_s2 == c1 and c2_s2 == c2):
            return s2
        else:
            if (c1_s3 == c1 and c2_s3 == c2):
                return s3
            else:
                if (c1_s4 == c1 and c2_s4 == c2):
                    return s4




def Sign(x, secret_key):
    r = 0
    while(True):
        formated_X, noz = Formatting(x, r, public_key)

        p = secret_key[0]
        q = secret_key[1]

        if (jacobi_symbol(formated_X, p) == 1 and jacobi_symbol(formated_X, q) == 1):
            k1, k2, k3, k4 = FindSquareRoots(x, p, q)
            vars = [k1, k2, k3, k4]
            signature = random.sample(vars, 1)
            return formated_X, signature[0]
        else:
            r = r + 1



def Verify(message, n):
    s = message[1]
    m = message[0]
    print("value: ", pow(s, 2, n))
    value = s*s % n
    un_value = Unformatting(value, n, 123)

    if (m == un_value):
        return "Verified"
    else:
        return "Not verified"


def FindSquareRoots(y, p, q):
    n = p * q
    gcd, v, u = gcdExtended(p, q)

    s1 = pow(y, int((p+1)//4), p)
    s2 = pow(y, int((q+1)//4), q)

    m1 = (u * q * s1 + v * p * s2) % n
    m2 = (u * q * s1 - v * p * s2) % n
    m3 = (- u * q * s1 + v * p * s2) % n
    m4 = (- u * q * s1 - v * p * s2) % n

    return m1, m2, m3, m4

def inversedElement(a, n):
    gcd, inversed, u = gcdExtended(a, n)
    if(inversed > 0):
        return inversed
    else:
        return inversed + n

def AttackBob(t, n):
    # t - formatted
    y = pow(t, 2, n)
    return y
def AnswerAlice(y, secret_key, n):
    p = secret_key[0]
    q = secret_key[1]
    z1, z2, z3, z4 = FindSquareRoots(y, p, q)

    if (jacobi_symbol(z1, p) == jacobi_symbol(z1, q) == 1):
        return z1
    if (jacobi_symbol(z2, p) == jacobi_symbol(z2, q) == 1):
        return z2
    if (jacobi_symbol(z3, p) == jacobi_symbol(z3, q) == 1):
        return z3
    if (jacobi_symbol(z4, p) == jacobi_symbol(z4, q) == 1):
        return z4

    return None

def ReceiveAlice(t, z, n):
    if(z == t or z == n - t):
        return "Send another t!"
    if(z != t or z != n - t):
        gcd, v, u = gcdExtended(t+z, n)
        return gcd


# array_of_primes = []
#
# while len(array_of_primes) != 4:
#         n = 128
#         prime_candidate = getLowLevelPrime(n)
#         if not isMillerRabinPassed(prime_candidate):
#             continue
#         else:
#             if(checkForm(prime_candidate) == 1):
#                 array_of_primes.append(prime_candidate)
#
# print("Generated prime numbers: ", array_of_primes, "\n")
# p1 = array_of_primes[0]
# q1 = array_of_primes[1]

# генерація p і q
p1 = 199931362534263207371601523109648080339
q1 = 321670935710401482198365577125950590767

# генерація ключів
secret_key, public_key = GenerateKeyPair(p1, q1)
b = 3

print("Secret key: ", secret_key)
print("Public key: ", hex(public_key), '\n')

# створення повідомлення
M = 0xafffabcefa123907
print("M: ", hex(M))
print("Length of M: ", len(hex(M)), '\n')

print("Public key: ", hex(public_key))
print("Length of public key: ", len(hex(public_key)), '\n')
#
# форматування
formatedM, number_of_zeros = Formatting(M, 2, public_key)
print("Formatted M: ", hex(formatedM))
print("Length of formatted M: ", len(hex(formatedM)), '\n')

# # розформатування
unformattedM = Unformatting(formatedM, public_key, number_of_zeros)
print("Unformatted M: ", hex(unformattedM))
print("Length of unformatted M: ", len(hex(unformattedM)), '\n')


# # шифрування
modulus1 = 0x8F819D172A32BE12DFF6A51C17E27B333EA1DAA34C47F88B5B1EF52EBB5A045D
b1 = 0x522BB7F62AD8E2F81D5A0FA1127983E0E9F2B48C6B2C3791E8A536CB6ED1D7B8

encrypted_message = Encrypt(formatedM, modulus1, b1)

print("Encrypted message: ", encrypted_message)
print("Encrypted message HEX: ", hex(encrypted_message[0]), '\n')

# # розшифрування
# message_from_server = [0x6ABF609FE8349C502E9AA64455F174332515E2587413DED1551496C18F4AEA64, 0, 1]
#
# decrypted_message = Decrypt(message_from_server, b1, secret_key, modulus1)
# print("Decrypted message UNFORMATTED: ", decrypted_message)
# #print("Decrypted message UNFORMATTED HEX: ", hex(decrypted_message))
#
# number_of_zeros_from_server = len(decToBin(modulus1)) - len(decToBin(0x123abc123)) - 16 - 64
# print("Number of zeros from server", number_of_zeros_from_server)
#
# received_message = Unformatting(decrypted_message, modulus1, number_of_zeros_from_server)
# print("Decrypted message: ", hex(received_message))
#
#
# # test
# MM = 0x123123123
# print("MM: ", hex(MM))
# newM, aa = Formatting(MM, 5, modulus1)
# print("newM: ", hex(newM))
# newM_unf = Unformatting(newM, modulus1, aa)
# print("newM_unf: ", hex(newM_unf))
#
# # підпис
# message_to_sign = 0x123
# print("Message to sign: ", hex(message_to_sign))
#
# signed_message = Sign(message_to_sign, secret_key)
# print("Signed message: ", signed_message)
# print("Formated text: ", hex(signed_message[0]))
# print("Signatrue HEX: ", hex(signed_message[1]), '\n')


# # перевірка підпису
print('\n')
message_to_verify = 0xabcdef
server_signature = 0x2B2E76044441A708F374C95DEFA6FF6CA60AC8A05AE1526FBB2E52F544CB8BC3
message = [message_to_verify, server_signature]
# formatted_message_to_verify, noz = Formatting(message_to_verify, b1, modulus1)
# print("formatted_message_to_verify: ", hex(formatted_message_to_verify))

#message1 = [formatted_message_to_verify, server_signature]
#
# print("Message: ", hex(message1[0]))
# print("Message: ", hex(message1[1]))

print("Verification state: ", Verify(message, modulus1))

#print(hex(Unformatting(formatted_message_to_verify, modulus1, noz)))


# атака
modulus_saitus = 0x8B30920793936DE814DACD0444EC0689431B8EBFB1EB007F3FF81874D80F5D7CF1A3EA9C8C9463E42030796386CF4E43925FD86B2DCF69A0DC9E46FDCC9BF710CB37F2CD6ECC2A27A6B03B75FE72B6E79AD18FCDEC876BE3E4EAB8228F0030F780E3CF88A863A3F7DB60EC345AA3B6CEA71DC990DC45E04E750EFC3B601C4AAA091C8C4DFE596AAB9B50190BCD6DD65680058B2CA139B356AD3E4558C8B0CD323FBA1336EA08DC6F05B22DFF34E64300518F32DE550196C85B70383DD9AFF8E6EF46FD554F6D4AAC95CD9327A8E577DFDF121D7AC0C8FB6A87C5A734CA3FE70A0FCFFDAC1D634A0643F752AEEB5F689C6EED422165CF3E20DA74161B5B804471
print('\n')
print("n:", hex(modulus_saitus))
t = 0xabcabcabc
y = pow(t, 2, modulus_saitus)
print("y: ", hex(y))

root = 0x7CACB8CCE37A3F29FDE6881A17D98BAB37E6B511E4DDE71467CC4C575017059E60DDD50DAC06E661CC2DFD6D920C783BA599A97582B6532601A383CA7BDEDD8D8B5EBE6E27E92B8FEAFB6EA5BA85C446EC73BAD12D10A28BE90ECCEFFF576701E45A93792951C81EC0DB6EA10082028237F20042FBB471CB5368480E873084A1FE1DD2D8FCA04373B1C6057EB1D7DA9382CDCB88EAA70D09582FFE4416AA5B1AE1D0DD2B6C279403754D093B6BA4B2C3CCBF9069AB47F047AF3D5147ED74B9D7B71438F9D302DB2BE2999269A2F7DAA5419BA79A461F18EF5B179EA5B7879E71FB201D84B0AC2B31B7D71A4702D2ED71BA13C2B9D98657F0D475181F5CF4F627
#p, u, v = gcdExtended(t + root, modulus_saitus)
p = math.gcd(t + root, modulus_saitus)

print("p: ", hex(p))

q = modulus_saitus//p

print("q: ", hex(int(q)))

