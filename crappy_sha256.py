# sources: https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/, https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf, https://www.youtube.com/watch?v=f9EbD6iY9zI
import time
import hashlib

def sha256(input_str): # accepts a string of 1's and 0's
    # padding
    input_str = input_str.replace(' ','')
    binstr = input_str + '1' # append 1 to end
    debug('binstr: ' + binstr)
    binstr += '0' * (512 - len(binstr)%512 - 64) # add 0's until lenghts is a multiple of 512, then subtract 64
    binstr += zero_pad(bin(len(input_str))[2:], 64) # appends 64 bit integer of original filesize

    debug('padding complete')
    debug(binstr)

    # initializing constants
    hash_constants = get_hash_constants()
    round_constants = get_round_constants()

    #hashing (get it? so space so its hashtag hashing? okay yeah its not that funny)
    for i in range(len(binstr)%512 + 1): # for each 512 bit chunk

        chunk = binstr[512*i:512*(i+1)]
        debug('chunk: ' + chunk)

        # split chunk into 16 32 bit long words
        words = []
        for ii in range(0,512,32):
            words.append(chunk[ii:ii+32])

        # add 48 words to get 64 total
        for ii in range(48):
            words.append('0'*32)
        debug('words:\n' + '\n'.join(words))

        # start doing stuff
        for ii in range(16,64):
            s0 = sigma0(words[ii-15])
            s1 = sigma1(words[ii-2])
            words[ii]=add(words[ii-16],s0, words[ii-7], s1)
            debug(str(ii) + ' ' + words[ii])

        debug('new words:\n' + '\n'.join(words))

        a = hash_constants[0]
        b = hash_constants[1]
        c = hash_constants[2]
        d = hash_constants[3]
        e = hash_constants[4]
        f = hash_constants[5]
        g = hash_constants[6]
        h = hash_constants[7]

        debug('set a,b,c,d,e,f,g,h to hash constants:\n'+'\n'.join(hash_constants))

        # "compression loop"
        for ii in range(64):
            s1 = str_xor(str_xor(rightrotate(e,6),rightrotate(e,11)), rightrotate(e,25))
            ch = str_xor(str_and(e,f), str_and(str_not(e), g))
            temp1 = add(h,s1,ch,round_constants[ii],words[ii])
            s0 = str_xor(str_xor(rightrotate(a,2), rightrotate(a, 13)), rightrotate(a,22))
            maj = str_xor(str_xor(str_and(a,b), str_and(a,c)), str_and(b,c))
            temp2 = add(s0, maj)
            h,g,f,e,d,c,b,a = g,f,e,add(d,temp1),c,b,a,add(temp1,temp2)
            debug('finished compression loop: ' + str(ii) + f'\na={a}\nb={b}\nc={c}\nd={d}\ne={e}\nf={f}\ng={g}\nh={h}', delay=0.1)

        debug(f'''about to modify constants:
hash_constants[0]={hash_constants[0]}
hash_constants[1]={hash_constants[1]}
hash_constants[2]={hash_constants[2]}
hash_constants[3]={hash_constants[3]}
hash_constants[4]={hash_constants[4]}
hash_constants[5]={hash_constants[5]}
hash_constants[6]={hash_constants[6]}
hash_constants[7]={hash_constants[7]}''')

        # modify final values
        hash_constants[0] = add(hash_constants[0], a)
        hash_constants[1] = add(hash_constants[1], b)
        hash_constants[2] = add(hash_constants[2], c)
        hash_constants[3] = add(hash_constants[3], d)
        hash_constants[4] = add(hash_constants[4], e)
        hash_constants[5] = add(hash_constants[5], f)
        hash_constants[6] = add(hash_constants[6], g)
        hash_constants[7] = add(hash_constants[7], h)

        debug(f'''modified constants:
hash_constants[0]={hash_constants[0]}
hash_constants[1]={hash_constants[1]}
hash_constants[2]={hash_constants[2]}
hash_constants[3]={hash_constants[3]}
hash_constants[4]={hash_constants[4]}
hash_constants[5]={hash_constants[5]}
hash_constants[6]={hash_constants[6]}
hash_constants[7]={hash_constants[7]}''')

        debug('finished chunk ' + str(i))

    final_hash = ''.join(hash_constants)
    debug('hashing complete:\n' + final_hash)
    final_hash = hex(int(final_hash,2))[2:]
    debug('converting to hex:\n' + str(final_hash))
    return final_hash


def sigma0(z):
    a = rightrotate(z, 7)
    b = rightrotate(z, 18)
    c = rightshift(z,3)
    ab = str_xor(a,b)
    abc = str_xor(ab,c)
    return abc

def sigma1(z):
    a = rightrotate(z, 17)
    b = rightrotate(z, 19)
    c = rightshift(z,10)
    ab = str_xor(a,b)
    abc = str_xor(ab,c)
    return abc

def SIGMA0(z):
    a = rightrotate(z, 2)
    b = rightrotate(z, 13)
    c = rightrotate(z, 22)
    ab = str_xor(a,b)
    abc = str_xor(ab,c)
    return abc

def SIGMA1(z):
    a = rightrotate(z, 6)
    b = rightrotate(z, 11)
    c = rightrotate(z, 25)
    ab = str_xor(a,b)
    abc = str_xor(ab,c)
    return abc

def choice(a,b,c):
    # for each bit in a, if 1 that bit in result is from b, if 0 that bit in result is from c
    result = []
    for i in range(len(a)):
        if a[i] == '1':
            bit = b[i]
        elif a[i] == '0':
            bit = c[i]
        result.append(bit)
    return ''.join(result)

def majority(a,b,c):
    res = ''
    for i in range(min(len(a),len(b),len(c))): # for each bit in smallest input (they should all be the same size tho)
        scores = {'0':0, '1':0}
        # I could do this more efficient with a loop, but this is more readable
        scores[a[i]]+=1
        scores[b[i]]+=1
        scores[c[i]]+=1
        if scores['0'] > scores['1']:
            res += '0'
        else: # scores['0'] and scores['1'] will never be equal, so '1' must be greater
            res += '1'
    return res



def zero_pad(txt, num):
    return '0' * (num-len(txt)) + txt

def get_hash_constants():
    # the hex representation of the first 32 bits of the decimal part of the first 8 primes. its like a constant thing in sha256
    first_8_primes = [2,3,5,7,11,13,17,19]
    res = []
    for prime in first_8_primes:
        sqrt = prime**0.5
        decimal = sqrt - int(sqrt)
        res.append(zero_pad(bin(int(decimal * 2**32))[2:34], 32))
    return res


def get_round_constants():
    # my attempt at generating it
    first_64_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311]
    res = []
    for prime in first_64_primes:
        cube_root = prime**(1/3)
        decimal_part = cube_root - int(cube_root)
        decimal_part_as_int = int(decimal_part * 2**32)
        res.append(zero_pad(bin(decimal_part_as_int)[2:34], 32))
    return res


def rightrotate(txt, num): # moves rightmost digit to leftmost position this many times
    for i in range(num):
        txt = txt[-1] + txt[:-1]
    return txt

def rightshift(txt, num): # again, I know, this is a horrible way to do it. but Im already commited to the whole string thing
    return '0'*num + txt[:len(txt)-num]

def str_xor(a, b): # I know this is already an operator in python but Im doing all of this in strings and that does like, actual binary.
    length = min(len(a),len(b)) # result will be length of shortest input
    result = ['0'] * length # initialize result
    for i in range(length):
        result[i] = ['0','1'][a[i] != b[i]] # xor each bit and store in result. with only 1 & 0, a xor b is same as a != b
    return ''.join(result)

def str_not(a): # because 'not' is already taken
    return str_xor(a, '1'*len(a))

def str_and(a,b):
    return majority(a,b,'0'*len(a)) # kind of a hacky way to do it but it works

def str_or(a,b):
    return majority(a,b,'1'*len(a)) # again, kind of a hacky way to do it but whatever

def add(*args):
    s = 0 # for sum
    for arg in args:
        s+=int(arg,2)
    s = s % (2**32)
    s = bin(s)[2:] # trims "0b" from start
    s = zero_pad(s, 32)
    return s

def debug(txt, delay=0.5):
    dbg = True
    if dbg:
        print('\n\n' + str(txt), end='')
        time.sleep(delay)

def str_to_binstr(txt):
    binstr = ''
    for char in txt:
        if type(char) == str:
            char = bin(ord(char))[2:]
        elif type(char) == int: # char in bytestring acts as integer
            char = bin(char)[2:]
        char = zero_pad(char, 8)
        binstr += char
    return binstr

def file_to_binstr(filename):
    with open(filename,'rb') as f:
        contents = f.read()
    return str_to_binstr(contents)


debug('dbg is set to True. to not see a whole bunch of text, change that to false in the \'debug\' function')
print(sha256(str_to_binstr('hello, world')))
# sha256(str_to_binstr('hello, world'))

# import timeit
# def time_my_func():
#     sha256(str_to_binstr(b'hello, world'))
# def time_builtin():
#     hashlib.sha256(b'hello, world').hexdigest()
# print('mine\t',timeit.timeit(time_my_func, number=1)) # running mine once = running the builtin 11000 times. oof
# print('builtin\t',timeit.timeit(time_builtin, number=11000))
