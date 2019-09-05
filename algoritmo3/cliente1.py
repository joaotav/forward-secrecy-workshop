#!/usr/bin/env python3
import socket, hmac, hashlib, sys, hkdf
from cryptography.fernet import Fernet
from comandos_2clientes import * # Importa os comandos PUT, PUT_ACK, GET, GET_ACK, e NOTIFY
from comandos_genericos import *


def main():
    nonce_cliente = 0
    sock = conectar2(PORTA, ID_CLIENTE) # Conecta-se com o servidor no IP local e na PORTA escolhida
    p, g = gerar_parametros()
    diffie_hellman_cliente(p,g,sock)
    sock.send(bytes(adicionar_padding(ID_CLIENTE), 'utf-8')) # Informa o ID do cliente
    resposta = remover_padding(sock.recv(TAM_PAYLOAD)) # Recebe a resposta do servidor
    print(resposta)
    aviso_pendentes = remover_padding(sock.recv(TAM_PAYLOAD)) # Recebe a resposta do servidor
    print(aviso_pendentes)
    publicar_mensagem(sock, nonce_cliente, 'G1', 'Olá grupo!', CHAVE_SECRETA)
    sock.close()
    print("[+] Conexão com o servidor encerrada.")


if len(sys.argv) < 2:
    print(f"[+] Utilização: {sys.argv[0].lstrip('./')} <porta>")
    print("[+] <porta> : Porta da rede na qual o servidor vai operar")
    raise SystemExit

try:
    PORTA = int(sys.argv[1])
except ValueError:
    print("[+] Por favor utilize somente números inteiros para a porta.")
    raise SystemExit


TAM_PAYLOAD = 512
ID_CLIENTE = 'cliente1'
CHAVE_SECRETA = b'WRprQNey0P5VH1JoCcMW-2PW6GZjKxIq6unPLF8QCG8='


main()
