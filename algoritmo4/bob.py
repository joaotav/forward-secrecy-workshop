#!/usr/bin/env python3
import socket, hmac, hashlib, sys, math, random, hkdf, os, base64
from comandos import *

TAM_PAYLOAD = 512

def diffie_hellman(cliente):
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


def main(porta):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Impede que o socket fique ocupado após a execução
    sock.bind((socket.gethostname(), porta)) # Define endereço e porta do socket
    sock.listen() # Aguarda conexões no endereço especificado

    cliente, endereco = sock.accept() # Aceita solicitações de conexão
    print(f"[+] Conexão com {endereco} estabelecida.\n")
    diffie_hellman(cliente)
    print(f"\n[+] Fim da conexão com {endereco}.\n")
    sock.close()


if len(sys.argv) < 2:
    print(f"[+] Utilização: {sys.argv[0].lstrip('./')} <porta>")
    print("[+] <porta> : Porta da rede na qual o servidor irá operar")
    raise SystemExit

try:
    porta = int(sys.argv[1])
except ValueError:
    print("[+] Por favor utilize somente números inteiros para a porta.")
    raise SystemExit

main(porta)
