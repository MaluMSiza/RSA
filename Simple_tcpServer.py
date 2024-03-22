from socket import *
serverPort = 12000
serverSocket = socket(AF_INET,SOCK_STREAM)

import random

first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                    31, 37, 41, 43, 47, 53, 59, 61, 67,
                    71, 73, 79, 83, 89, 97, 101, 103,
                    107, 109, 113, 127, 131, 137, 139,
                    149, 151, 157, 163, 167, 173, 179,
                    181, 191, 193, 197, 199, 211, 223,
                    227, 229, 233, 239, 241, 251, 257,
                    263, 269, 271, 277, 281, 283, 293,
                    307, 311, 313, 317, 331, 337, 347, 349]

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)

def getLowLevelPrime(n):
    while True:
        pc = nBitRandom(n)
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else:
            return pc

def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True

def gerar_chaves_rsa(tamanho_bits):
    while True:
        p = getLowLevelPrime(tamanho_bits)
        q = getLowLevelPrime(tamanho_bits)
        N = p * q
        phi = (p - 1) * (q - 1)
        
        e = random.randint(2, phi - 1)
        while gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        
        d = mod_inverse(e, phi)
        
        chave_publica = (e, N)
        chave_privada = (d, N)
        
        return chave_publica, chave_privada

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def tratamentoString(string):
    valores = string[1:-1].split(',')
    return (int(valores[0]), int(valores[1]))

def criptografar(mensagem, chave_publica):
    e, N = chave_publica
    mensagem_codificada = [pow(ord(char), e, N) for char in mensagem]
    return mensagem_codificada

def decriptografar(mensagem, chave_privada):
    d, N = chave_privada
    aux = [str(pow(char, d, N)) for char in mensagem]
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)

bobPublickey, bobPrivatekey = gerar_chaves_rsa(4096)
print("Chave publica enviada(Bob): OK..")
serverSocket.bind(("",serverPort))
serverSocket.listen(5)
print ("TCP Server\n")
connectionSocket, addr = serverSocket.accept()
connectionSocket.send(str(bobPublickey).encode())  


alicePublicKey = str(connectionSocket.recv(8192).decode()) 
print("Chave publica obtida da Alice: OK..") 

mensagemAlice = connectionSocket.recv(65000) 
print("Mensagem recebida?: OK...") 
lista_de_inteiros = list(map(int, mensagemAlice.decode().split(',')))
mensagem_decriptografada = decriptografar(lista_de_inteiros, bobPrivatekey)
print("...Decripto:", mensagem_decriptografada) 

mensagemMaiuscula = mensagem_decriptografada.upper()
print("...Maiscula:", mensagemMaiuscula) 

mensagem_criptografada=criptografar(mensagemMaiuscula, tratamentoString(alicePublicKey))
lista_string = ','.join(map(str, mensagem_criptografada))
connectionSocket.send(lista_string.encode())
connectionSocket.close()