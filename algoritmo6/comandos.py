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
    hash = hashlib.sha256()
    hash.update(semente_idvv)
    hash.update(chave_idvv)
    idvv = hash.hexdigest().encode() # Hash da concatenação dos dados passados para a função sha256
    return idvv


def idvv_next(semente_idvv, chave_idvv, idvv):
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
    # Computa a chave de recuperação k_rec usando iDVV
    idvv = idvv_init(semente_idvv, chave_idvv)
    idvv, semente_idvv = idvv_next(semente_idvv, chave_idvv, idvv)
    random = idvv

    k_rec = hashlib.sha256()
    k_rec.update(chave_mestra)
    k_rec.update(random)
    k_rec = k_rec.hexdigest() # k_rec = H (chave_mestra || random)
    return k_rec, random


def key(destino, nonce, ack_nonce, chave):
    payload = ''
    payload += "KEY" + '/' # Comando REC
    payload += str(nonce) + '/'
    nonce_criptografado = criptografar(str(ack_nonce), chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += nonce_criptografado.decode()
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(adicionar_padding(payload), 'utf-8'))
    return


def rec(destino, nonce, random, chave):
    payload = ''
    payload += "REC" + '/' # Comando REC
    payload += str(nonce) + '/'
    payload += str(random[2:-1])
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(adicionar_padding(payload), 'utf-8'))
    return


def rec_ack(destino, nonce, ack_nonce, chave):
    payload = ''
    payload += "RCA" + '/' # Comando REC_ACK
    payload += str(nonce) + '/'
    nonce_criptografado = criptografar(str(ack_nonce), chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += nonce_criptografado.decode()
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(adicionar_padding(payload), 'utf-8'))
    return


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


def gerar_hmac(chave, info):
    h = hmac.new(chave, info.encode(), hashlib.sha256)
    return h.hexdigest()


def check_nonce(nonce, nonce_recebido):
    if nonce != nonce_recebido:
        print("[+] Erro na sincronia das mensagens!")
        raise SystemExit
    return

def adicionar_padding(mensagem):
    encoded_size = len(bytes(mensagem.encode()))
    padding = (TAM_PAYLOAD - encoded_size + len(mensagem))
    # Preenche o final da mensagem com espaços vazios
    return mensagem.ljust(padding, ' ')


def remover_padding(mensagem):
    # Remove o preenchimento ao final da mensagem
    return mensagem.decode().rstrip(' ')


def extrair_dados(payload, chave):
    if verificar_hmac(payload, chave) == 'NOK': # Verifica a integridade da mensagem
        print("[+] HMAC incompatível com a mensagem recebida.")
        raise SystemExit
    payload = remover_padding(payload)
    comando, nonce, dados = payload.split('/')
    if comando == 'KEY' or comando == "REC_ACK":
        dados = decodificar(dados, chave)
    return comando, int(nonce), dados
