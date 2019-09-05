#!/usr/bin/env python3
import socket, hmac, hashlib, sys, math, random, os, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

TAM_PAYLOAD = 512

def derivar_chave(chave):
    ''' Deriva uma chave para ser usada com o algoritmo de criptografia fernet
    a partir da chave gerada pelo processo de diffie-hellman '''
    salt = b''
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000,
    backend=default_backend())
    chave = base64.urlsafe_b64encode(kdf.derive(chave))

    return chave

def conectar(PORTA):
    ''' Estabelece uma conexao com o endereco 127.0.0.1 e a porta especificada '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Impede que o socket fique ocupado após a execução
    try:
        sock.connect((socket.gethostname(), PORTA)) # Conecta com o servidor na porta 5555
        print("[+] Conexão com {} estabelecida.\n".format(sock.getsockname()))
    except ConnectionError:
        print("[+] Erro na conexão com o servidor.")
        raise SystemExit
    return sock


def idvv_init(semente_idvv, chave_idvv):
    ''' Inicia um iDVV, dada uma semente e uma chave '''
    hash = hashlib.sha256()
    hash.update(semente_idvv)
    hash.update(chave_idvv)
    idvv = hash.hexdigest().encode() # Hash da concatenação dos dados passados para a função sha256
    return idvv


def idvv_next(semente_idvv, chave_idvv, idvv):
    ''' Evolui um iDVV, dada uma semente, uma chave e o idvv atual '''
    nova_semente = hashlib.sha256()
    nova_semente.update(semente_idvv)
    nova_semente.update(idvv)
    semente_idvv = nova_semente.hexdigest().encode()

    novo_idvv = hashlib.sha256()
    novo_idvv.update(semente_idvv)
    novo_idvv.update(chave_idvv)
    idvv = novo_idvv.hexdigest()

    return semente_idvv, idvv


def computar_chave_rec(semente_idvv, chave_idvv, chave_mestra):
    ''' Computa uma chave de recuperação k_rec usando iDVV '''
    idvv = idvv_init(semente_idvv, chave_idvv)
    idvv, semente_idvv = idvv_next(semente_idvv, chave_idvv, idvv)
    random = idvv

    k_rec = hashlib.sha256()
    k_rec.update(chave_mestra)
    k_rec.update(random)
    k_rec = k_rec.hexdigest() # k_rec = H (chave_mestra || random)
    return k_rec, random


def key(destino, nonce, ack_nonce, chave):
    ''' Envia um comando KEY, avisando que a chave de recuperacao foi gerada com sucesso '''
    payload = ''
    payload += "KEY" + '/' # Comando REC
    payload += str(nonce) + '/'
    nonce_criptografado = criptografar(str(ack_nonce), chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += nonce_criptografado.decode()
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(adicionar_padding(payload), 'utf-8'))
    return


def rec(destino, nonce, random, chave):
    ''' Envia um comando REC, solicitando a geracao de uma chave de recuperacao '''
    payload = ''
    payload += "REC" + '/' # Comando REC
    payload += str(nonce) + '/'
    payload += str(random[2:-1])
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(adicionar_padding(payload), 'utf-8'))
    return


def rec_ack(destino, nonce, ack_nonce, chave):
    ''' Envia um comando REC_ACK para notificar o recebimento de um comando REC '''
    payload = ''
    payload += "RCA" + '/' # Comando REC_ACK
    payload += str(nonce) + '/'
    nonce_criptografado = criptografar(str(ack_nonce), chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += nonce_criptografado.decode()
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(adicionar_padding(payload), 'utf-8'))
    return


def verificar_hmac(payload, chave):
    ''' Verifica a integridade do payload recebido atraves do codigo HMAC '''
    payload = remover_padding(payload)
    msg_hmac = payload[-64:] # Os últimos 64 caracteres do payload são o HMAC
    dados = payload[:-64]

    # Computa novamente o HMAC da mensagem
    h = hmac.new(chave, dados.encode(), hashlib.sha256)
    if h.hexdigest() == msg_hmac: # Se o HMAC bate com o codigo recebido
        return 'OK'
    else:
        return 'NOK'


def criptografar(mensagem, chave):
    ''' Criptografa uma string usando uma chave e o algoritmo Fernet '''
    mecanismo = Fernet(chave)
    return mecanismo.encrypt((mensagem).encode())


def decodificar(mensagem, chave):
    ''' Decodifica uma mensagem utilizando uma chave e o algoritmo Fernet '''
    mecanismo = Fernet(chave)
    mensagem = mecanismo.decrypt(mensagem.encode()).decode()
    return mensagem


def gerar_hmac(chave, info):
    ''' Gera um codigo HMAC para permitir a verificacao da integridade de uma string '''
    h = hmac.new(chave, info.encode(), hashlib.sha256)
    return h.hexdigest()


def check_nonce(nonce, nonce_recebido):
    ''' Verifica se o nonce recebido e igual ao nonce esperado '''
    if nonce != nonce_recebido:
        print("[+] Erro na sincronia das mensagens!")
        raise SystemExit
    return

def adicionar_padding(mensagem):
    ''' Preenche a mensagem com espacos vazios ate atingir o tamanho do payload '''
    encoded_size = len(bytes(mensagem.encode()))
    padding = (TAM_PAYLOAD - encoded_size + len(mensagem))
    # Preenche o final da mensagem com espaços vazios
    return mensagem.ljust(padding, ' ')


def remover_padding(mensagem):
    ''' Remove os espacos vazios ao final da mensagem, recuperando os dados originais '''
    # Remove o preenchimento ao final da mensagem
    return mensagem.decode().rstrip(' ')


def extrair_dados(payload, chave):
    ''' Extrai os dados presentes nos diferentes campos da mensagem recebida '''
    if verificar_hmac(payload, chave) == 'NOK': # Verifica a integridade da mensagem
        print("[+] HMAC incompatível com a mensagem recebida.")
        raise SystemExit
    payload = remover_padding(payload)
    comando, nonce, dados = payload.split('/')
    if comando == 'KEY' or comando == "REC_ACK":
        dados = decodificar(dados, chave)
    return comando, int(nonce), dados

### Cliente
def diffie_hellman_cliente(p, g, sock):
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

####  DH  servidor
def diffie_hellman_servidor(cliente):
    mensagem = cliente.recv(TAM_PAYLOAD)
    mensagem = remover_padding(mensagem)
    p, g = mensagem.split('/') # Recupera os valores de p e g
    p = int(p) # Converte a string recebida para inteiro
    g = int(g)
    B = random.randint(1,10000)
    b = g ** B % p

    mensagem = str(b)
    mensagem = adicionar_padding(mensagem)
    cliente.send(bytes(mensagem, 'utf-8'))

    resposta = cliente.recv(TAM_PAYLOAD)
    resposta = remover_padding(resposta)
    a = int(resposta) # Armazena o valor 'b' recebido do servidor

    chave_compartilhada = str(a ** B % p)
    print("[+] Chave compartilhada gerada: {}".format(chave_compartilhada))

    # Deriva uma chave que possa ser usada pelo algoritmo de criptografia
    chave_compartilhada = derivar_chave(bytes(chave_compartilhada, 'utf-8'))
    print(f"[+] Chave derivada: {chave_compartilhada.decode()}")

    nova_chave = cliente.recv(TAM_PAYLOAD) # Recebe do cliente a nova chave gerada com hkdf

    # Verifica a integridade dos dados usando HMAC
    if verificar_hmac(nova_chave, chave_compartilhada) == 'NOK':
        print("[+] O HMAC da mensagem recebida não corresponde aos dados.")
        raise SystemExit

    nova_chave = remover_padding(nova_chave)
    nova_chave = nova_chave[:-64] # Retira os últimos 64 bytes da mensagem (HMAC)
    chave_compartilhada = decodificar(nova_chave, chave_compartilhada)

    chave_compartilhada = bytes(chave_compartilhada[2:-1], 'utf-8') # Converte a chave de str para bytes
    print("[+] Nova chave gerada: {}".format(chave_compartilhada.decode()))

    mensagem = "[+] Nova chave recebida pelo servidor."
    mensagem = criptografar(mensagem, chave_compartilhada).decode()
    mensagem += gerar_hmac(chave_compartilhada, mensagem.encode())
    mensagem = adicionar_padding(mensagem)
    cliente.send(bytes(mensagem, 'utf-8')) # Responde ao cliente dizendo que recebeu a nova chave
