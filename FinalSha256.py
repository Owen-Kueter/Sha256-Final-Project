#Implementation based on the fips 180-2 Secure Hash Standards
#https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
#Additional Resource 
#https://www.researchgate.net/file.PostFileLoader.html?id=534b393ad3df3e04508b45ad&assetKey=AS%3A273514844622849%401442222429260
#Code by Owen Kueter

initHashVals = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

#Circular shift of x by n places to the right
def rotr(x, n):
    return (x >> n) | (x << 32 - n)

#If x is 1 return y,
#Else if x is 0 return z
def ch(x, y, z):
    return (x & y) ^ (~x & z)

#Returns True if the majority of the 3 input bits are True
def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sum0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sum1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def sha256(message):
    message = bytearray(message,'utf-8')
    #Each character is 8 bits
    msgLength = len(message)*8 
    #Pad the additional bit 
    message.append(0x80)
    #Get the total number of bits and determine amount of padding       
    padLength = len(message) * 8    
    k = (448-padLength) % 512
    #Pad additional bits if message isn't long enough
    message += b'\x00'*(k//8) 
    #lastly pad the length of the of the initial message
    message += msgLength.to_bytes(8,byteorder='big') 
    
    #Msg blocks 512-bit
    blocks = [] 
    for i in range(0, len(message), 64): 
        blocks.append(message[i:i+64])
        
    #Determine how many blocks you have to iterate over
    Nblock = (len(message)*8)//512
    
    #The initial hash values
    h0,h1,h2,h3,h4,h5,h6,h7 = initHashVals
    
    for index, message_block in enumerate(blocks):
        messageSched = []
        
        for t in range(0, 64):
            #The first 16 32bit words are taken from the message
            if t <= 15:
                messageSched.append(bytes(message_block[t*4:(t*4)+4]))
            else:
    
                #The remaining 48 are with this formula 
                word2 = sigma1(int.from_bytes(messageSched[t-2], 'big'))
                word7 = int.from_bytes(messageSched[t-7], 'big')
                word15 = sigma0(int.from_bytes(messageSched[t-15], 'big'))
                word16 = int.from_bytes(messageSched[t-16], 'big')
                #Addition (+) is performed modulo 2^32
                schedule = ((word2 + word7 + word15 + word16) % 2**32).to_bytes(4, 'big')
                messageSched.append(schedule)
                
        #The working variables are the first 32 bits of the 
        #fractional part of the square roots of the first 8 prime numbers
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        
        #Construct the 64 chunks
        for t in range(64):
            t1 = ((h + sum1(e) + ch(e, f, g) + K[t] + int.from_bytes(messageSched[t], 'big')) % 2**32)
            t2 = (sum0(a) + maj(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32
    
    
        #Now we compute the new hash values for n blocks
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32
  
    result  = (h0).to_bytes(4, 'big')
    result += (h1).to_bytes(4, 'big')
    result += (h2).to_bytes(4, 'big')
    result += (h3).to_bytes(4, 'big')
    result += (h4).to_bytes(4, 'big')
    result += (h5).to_bytes(4, 'big')
    result += (h6).to_bytes(4, 'big')
    result += (h7).to_bytes(4, 'big')
    
    print(result.hex())
    return(result.hex())

message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
sha256(message)