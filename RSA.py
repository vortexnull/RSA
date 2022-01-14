"""
Name : Ishvik Kumar Singh
Entry no.: 2018EE10616
RSA Encryption and Decryption
"""

import secrets

class RSA:
    
    def __init__(self, keylength = 128):
        self.keylength = keylength
        self.n = 0
        self.pu = 0
        self.pr = 0

    # Computes gcd of a & b
    def gcd(self, a, b):

        while (b != 0):
            temp = a
            a = b
            b = temp % b

        return a

    # Computes gcd and coefficients of Bezout's Identity
    def xgcd(self, a, b):
        r, r1 = a, b
        s, s1 = 1, 0
        t, t1 = 0, 1

        while (r1 != 0):
            q = r // r1
            r, r1 = r1, r - q * r1
            s, s1 = s1, s - q * s1
            t, t1 = t1, t - q * t1
        
        # gcd => r, as + bt = r
        return r, s, t

    # Finds public key
    def findpublic(self, phi_n):
        e = 0

        # public key, e is co-prime with totient(n)
        while (self.gcd(e, phi_n) != 1):
            e = secrets.randbelow(phi_n)

        return e
    
    # Miller-Rabin primality test
    def MillerRabin(self, d, n):

        a = 3 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
 
        if (x == 1 or x == n - 1):
            return True

        while (d != n - 1):
            x = (x * x) % n
            d *= 2
 
            if (x == 1):
                return False
            elif (x == n - 1):
                return True

        return False
 
    # Runs Miller-Rabin test k times to check if a number is prime
    def isPrime(self, n, k):
        
        if (n <= 1 or n == 4):
            return False
        if (n <= 3):
            return True
    
        d = n - 1
        while (d % 2 == 0):
            d //= 2
    
        for i in range(k):
            if (self.MillerRabin(d, n) == False):
                return False
    
        return True
    
    # Finds primes, p and q such that n = p * q
    def findprimes(self, pu):
        p, q = 1, 1
        totient = 0

        while (pu >= totient):
            while (self.isPrime(p, 40) != True):
                p = secrets.randbelow(pu)

            while not(self.isPrime(q, 40) == True and q != p):
                q = secrets.randbelow(pu)
            
            totient = (p - 1) * (q - 1)

        return p, q

    # Generates public-private key pair for this node
    def keygen(self):
        check = 0

        while(check != 1): 
            e = 0

            while(e % 2 == 0):
                e = secrets.randbits(self.keylength)

            # pu => public key
            self.pu = e

            p, q = self.findprimes(e)
            self.n = p * q

            # phi_n => totient(n)
            phi_n = (p - 1) * (q - 1)

            temp = self.xgcd(self.pu, phi_n)
            # pr => private key; pr = inv(pu) modulo totient(n)
            self.pr = self.xgcd(self.pu, phi_n)[1] % phi_n

            # check = gcd(pu, totient(n)); should be 1 as pu must be co-prime with totient(n)
            check = temp[0]

        return self.n, self.pu, self.pr

    # Divides array of bytes into blocks and assigns an integer, blockInt < n to each block
    def getBlocks(self, textbytes, blocksize):
        blockInts = []

        for start in range(0, len(textbytes), blocksize):
            blockInt = 0

            for i in range(start, min(start + blocksize, len(textbytes))):
                blockInt += textbytes[i] * (256 ** (i % blocksize))
            
            blockInts.append(blockInt)

        blockInts.append(len(textbytes) % blocksize)

        return blockInts

    # Retrieves bytes corresponding to each block from integers assigned to respective blocks
    def getText(self, blockInts, blocksize):
        text = []

        textlength = blockInts.pop() + (len(blockInts) - 1) * blocksize

        for blockInt in blockInts:
            blocktext = []

            for i in range(blocksize - 1, -1, -1):
                if (len(text) + i < textlength):
                    bytenum = blockInt // (256 ** i)
                    blockInt = blockInt % (256 ** i)
                    
                    blocktext.insert(0, bytenum)

            text.extend(blocktext)

        return bytearray(text)

    # Implements RSA encryption
    def encrypt(self, plaintext, key):
        print("\n" +"Encrypting ...")
        e, n = key
           
        # blocksize must be less than the number of bytes in n
        blocksize = (n.bit_length() - 1) // 8
        blockInts = self.getBlocks(plaintext, blocksize)

        # Encrypting each block
        encrypt_blockInts = [pow(i, e, n) for i in blockInts]

        return ' '.join(map(str, encrypt_blockInts))

    # Implements RSA decryption
    def decrypt(self, ciphertext, key):
        print("\n" + "Decrypting ...")
        d, n = key

        # blocksize must be less than the number of bytes in n
        blocksize = (n.bit_length() - 1) // 8  
        blockInts = map(int, ciphertext.split(" "))

        # Decrypting each block
        decrypt_blockInts = [pow(i, d, n) for i in blockInts]
        plaintext = self.getText(decrypt_blockInts, blocksize)
        
        return plaintext

security = RSA(int(input("Enter key length: ")))
n, pu, pr = security.keygen()

print("\nGenerated Key Lengths {pu, pr}:", "{" + str(pu.bit_length()) + ",", str(pr.bit_length()) + "}", "bits")
print("Public Key, {pu, n} =", "{" + str(pu) + ",", str(n) + "}")
print("Public Key, {pr, n} =", "{" + str(pr) + ",", str(n) + "}")

inputfile = open("a.png", "rb")
P = inputfile.read()
inputfile.close()

ciphertext = open("ciphertext", "w")

encrypt_prompt = input("\nEnter public key, {pu, n} (leave blank to use the generated key): ")
if (encrypt_prompt == ""):
    pu, n = pu, n 
else:
    pu, n = [int(x) for x in encrypt_prompt.split()]

C = security.encrypt(P, (pu, n))
ciphertext.write(C)
print("Encryption done")
ciphertext.close()

ciphertext = open("ciphertext", "r")
C = ciphertext.read()
ciphertext.close()

outputfile = open("a1.png", "wb")

decrypt_prompt = input("\nEnter private key, {pr, n} (leave blank to use the generated key): ")
if (decrypt_prompt == ""):
    pr, n = pr, n 
else:
    pu, n = [int(x) for x in decrypt_prompt.split()]

outputfile.write(security.decrypt(C, (pr, n)))
print("Decryption done")
outputfile.close()
