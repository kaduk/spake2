# sage -pip install pycryptodome
# from Crypto.Hash import SHA256, HMAC

from struct import *

# P-256 constants and helper functions
px = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
py = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

FF = GF(p256)
EC = EllipticCurve([FF(p256 - 3), FF(b256)])
P = EC(FF(px), FF(py))

mcomp = 0x02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
ncomp = 0x03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
mx = 0x886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
nx = 0xd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49

my = 0x5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20
ny = 0x07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7

M = EC(FF(mx), FF(my))
N = EC(FF(nx), FF(ny))

def wrap_print(arg, *args):
    line_length = 70
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)

def print_integer(name, x):
    wrap_print(name + ' = 0x' + format(x, 'x').zfill(64))

def encode_point(point):
    return '04' + format(int(point[0]), 'x').zfill(64) + format(int(point[1]), 'x').zfill(64)

def print_point(name, point):
    wrap_print(name + ' = 0x' + encode_point(point))

def pack_point(point):
    return pack_len(bytes.fromhex(encode_point(point)))

def pack_len(data):
    return pack('<Q', len(data)) + data

def pack_string(s):
    return pack_len(s.encode('utf-8'))

def hkdf(ikm, info):
    return HKDF(ikm, 32, None, SHA256, 1, context=info)

def hmac(k, m):
    h = HMAC.new(k, digestmod=SHA256)
    h.update(m)
    return h.hexdigest()

def derive_keys(TT):
    # Ka || Ke = Hash(TT)
    sk = SHA256.new(data=TT).digest()
    Ka = sk[:16]
    Ke = sk[16:]
    wrap_print('Ka = 0x' + Ka.hex())
    wrap_print('Ke = 0x' + Ke.hex())

    # KDF(nil, Ka, "ConfirmationKeys") = KcA || KcB
    ck = hkdf(Ka, b'ConfirmationKeys')
    KcA = ck[:16]
    KcB = ck[16:]
    wrap_print('KcA = 0x' + KcA.hex())
    wrap_print('KcB = 0x' + KcB.hex())
    
    return Ke, KcA, KcB

def spake2(A, B):
    print("spake2: A='%s', B='%s'"%(A,B))
    w = int(FF.random_element())
    # Print w
    print_integer('w', w)
    
    # A generates key share S
    x = int(FF.random_element())
    print_integer('x', x)
    S = int(x) * P + w * M
    print_point('S', S)

    # B generates key share T
    y = int(FF.random_element())
    print_integer('y', y)
    T = int(y) * P + w * N
    print_point('T', T)

    # A computes shared key K
    K = x * (T - w * N)
    print_point('K', K)

    # B computes shared keys K
    assert K == y * (S-w*M)

    TT = pack_string(A)
    TT += pack_string(B)
    TT += pack_point(S)
    TT += pack_point(T)
    TT += pack_point(K)
    TT += pack_len(bytes.fromhex(format(w, '064x')))
    wrap_print('TT = 0x' + TT.hex())
    
    # Derive key schedule
#    Ke, KcA, KcB = derive_keys(TT)

    # MAC = HMAC(KcA/KcB, Y/X)
#    wrap_print('HMAC(KcA, Y) = 0x' + hmac(KcA, bytes.fromhex(TT)))
#    wrap_print('HMAC(KcB, X) = 0x' + hmac(KcB, bytes.fromhex(TT)))


spake2(A='server', B='client')
spake2(A='', B='client')
spake2(A='server', B='')
spake2(A='', B='')
