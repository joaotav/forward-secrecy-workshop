#!/usr/bin/env python3
import socket, hmac, hashlib, sys, math, random, hkdf, os, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TAM_PAYLOAD = 512

def derivar_chave(chave):
    ''' Deriva uma chave para ser usada com o algoritmo de criptografia fernet
    a partir da chave gerada pelo processo de diffie-hellman '''
    salt = b''
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000,
    backend=default_backend())
    chave = base64.urlsafe_b64encode(kdf.derive(chave))

    return chave


def gerar_hmac(chave, info):
    h = hmac.new(chave, info, hashlib.sha256)
    return h.hexdigest()


def verificar_hmac(payload, chave):
    payload = remover_padding(payload)
    msg_hmac = payload[-64:] # Os últimos 64 caracteres do payload são o HMAC
    dados = payload[:-64]
    h = hmac.new(chave, dados.encode(), hashlib.sha256)
    if h.hexdigest() == msg_hmac:
        return 'OK'
    else:
        return 'NOK'


def criptografar(mensagem, chave):
    mecanismo = Fernet(chave)
    return mecanismo.encrypt((mensagem).encode())


def decodificar(mensagem, chave):
    mecanismo = Fernet(chave)
    mensagem = mecanismo.decrypt(mensagem.encode()).decode()
    return mensagem


def eh_primo(num):
    ''' Retorna True se num for um número primo, do contrário retorna False '''
    if num == 1:
        return False # 1 não é primo

    divisor_maximo = math.floor(math.sqrt(num))
    for y in range(2, divisor_maximo + 1):
        if num % y == 0: # Se a operação de módulo retornar 0, num é divisível por y
            return False # Se num é divisível por y (y != 1 e y != num), num não é primo
    return True


def gerar_parametros():
    ''' Gera os parâmetros iniciais 'p' e 'g' da troca de chaves de Diffie-Hellman
        Descrição do processo: https://bit.ly/2YUHXSd'''
    q = random.randint(100000, 1000000) # Seleciona um valor inicial aleatório
    r = 1

    while True:
        if eh_primo(q): # Se o valor for primo, será usado
            break
        else:
            q += 1 # Se não for primo, incrementa e testa novamente

    while True:
        p = q * r + 1
        if eh_primo(p):
            break
        else:
            r += 1

    while True:
        u = random.randint(1,10000)
        g = (u ** ((p - 1)/q)) % p
        if g == 1:
            continue
        else:
            break

    return int(p), int(g)


def conectar(PORTA):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
        sock.connect((socket.gethostname(), PORTA))
        print("[+] Conexão com {} estabelecida.\n".format(sock.getsockname()))
    except ConnectionError:
        print("[+] Erro na conexão com o servidor.")
        raise SystemExit
    return sock


def adicionar_padding(mensagem):
    encoded_size = len(bytes(mensagem.encode()))
    padding = (TAM_PAYLOAD - encoded_size + len(mensagem))
    # Preenche o final da mensagem com espaços vazios
    return mensagem.ljust(padding, ' ')


def remover_padding(mensagem):
    # Remove o preenchimento ao final da mensagem
    return mensagem.decode().rstrip(' ')


def diffie_hellman(p, g, sock):
    mensagem = str(p) + '/' + str(g) # mensagem = valor p/valor g
    mensagem = adicionar_padding(mensagem) # Preenche a mensagem até atingir o tamanho do payload
    sock.send(bytes(mensagem, 'utf-8')) # Envia os parâmetros iniciais p e g para o servidor

    A = random.randint(1, 10000)
    a = g ** A % p

    resposta = sock.recv(TAM_PAYLOAD)
    resposta = remover_padding(resposta)
    b = int(resposta) # Armazena o valor 'b' recebido do servidor

    mensagem = str(a) # mensagem = valor a
    mensagem = adicionar_padding(mensagem)
    sock.send(bytes(mensagem, 'utf-8')) # Compartilha o valor gerado 'a' com o servidor

    chave_compartilhada = str(b ** A % p)
    print("[+] Chave compartilhada gerada: {}".format(chave_compartilhada))

    # Deriva uma chave que possa ser usada pelo algoritmo de criptografia
    chave_compartilhada = derivar_chave(bytes(chave_compartilhada, 'utf-8'))
    print(f"[+] Chave derivada: {chave_compartilhada.decode()}")

    k = hkdf.hkdf_extract(None, chave_compartilhada)

    nova_chave = hkdf.hkdf_expand(k) # Expande a chave utilizando hkdf
    nova_chave = derivar_chave(nova_chave)

    mensagem = str(nova_chave)
    mensagem = criptografar(mensagem, chave_compartilhada).decode()
    mensagem += gerar_hmac(chave_compartilhada, mensagem.encode())
    mensagem = adicionar_padding(mensagem)
    sock.send(bytes(mensagem, 'utf-8'))

    chave_compartilhada = nova_chave # Atualiza a chave para a nova chave gerada
    print("[+] Nova chave gerada: {}".format(chave_compartilhada.decode()))

    resposta = sock.recv(TAM_PAYLOAD)

    if verificar_hmac(resposta, chave_compartilhada) == 'NOK':
        print("[+] O HMAC da mensagem recebida não corresponde aos dados.")
        raise SystemExit

    resposta = remover_padding(resposta)
    resposta = resposta[:-64] # Retira os últimos 64 bytes da mensagem (HMAC)
    resposta = decodificar(resposta, chave_compartilhada)
    print(resposta)
    

def main(porta):
    sock = conectar(porta)
    p, g = gerar_parametros()
    diffie_hellman(p, g, sock)
    print("\n[+] Fim da conexão com o servidor.\n")
    sock.close()


if len(sys.argv) < 2:
    print(f"[+] Utilização: {sys.argv[0].lstrip('./')} <porta>")
    print("[+] <porta> : Porta da rede na qual o servidor está operando")
    raise SystemExit

try:
    porta = int(sys.argv[1])
except ValueError:
    print("[+] Por favor utilize somente números inteiros para a porta.")
    raise SystemExit

main(porta)
