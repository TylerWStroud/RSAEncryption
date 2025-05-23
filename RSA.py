import random
import time

def KeyGen(p,q):
    n = p*q
    euler_totient = (p-1)*(q-1)

    # defining a prime number
    def is_prime(x):
        if x < 2:
            return False
        for i in range(2, int(x**0.5)+1):
            if x%i == 0:
                return False
        return True

    # looking for all prime numbers within an integer
    def parse_primes(num):
        primes_array = []
        if num < 2:
            return primes_array

        for i in range(2, num+1):
            if(is_prime(i)):
                primes_array.append(i)

        return primes_array

    # creating an array of all prime numbers within Euler's totient
    e_primes = parse_primes(euler_totient)
    # creating an array of all primes that are less than n, and shares no common factors with the Euler's totient
    e_array = []
    for prime in e_primes:
        if euler_totient%prime != 0:
            e_array.append(prime)


    # picking an arbitrary prime number from primes array for public key
    e = random.choice(e_array)
    # finding multiplicative inverse of public key for private key
    d = pow(e, -1, euler_totient)

    public_key = [e, n]
    private_key = [d, n]
    return public_key, private_key

def RSA(data, key):
    output = None
    # checks for integer input
    def is_int(input):
        try:
            int(input)
            return True
        except ValueError:
            return False

    #decryption/encryption of integer data
    if(is_int(data)):
        return (int(data)**key[0])%key[1]
        #output = (int(data)**key[0])%key[1]

    #decryption/encryption of string data
    else:
        output = []
        for char in data:
            val = (ord(char)**key[0])%key[1]
            output.append(chr(val))

        return ''.join(output)

class Main:
    p, q = 811, 1103
    # timing KeyGen
    start = time.time()
    PU, PR = KeyGen(p,q)
    end = time.time()
    print(f"Using primes p = {p} and q = {q}\nKey gen time: {end-start:.2f} seconds")
    while True:
        plain_text = input("Enter your text to be encrypted: ")

        if(plain_text.lower() == "quit" or plain_text.lower() == "exit"):
            print("Exiting...")
            break

        # timing encryption and decryption
        e_start = time.time()
        encryption = RSA(plain_text, PU)
        e_end = time.time()
        d_start = time.time()
        decryption = RSA(encryption, PR)
        d_end = time.time()

        print("\nEncrypted: ",encryption, "\nDecrypted: ",decryption,
              f"\nIt took {e_end-e_start:.2f} seconds to encrypt, and {d_end-d_start:.2f} seconds to decrypt.\n")



