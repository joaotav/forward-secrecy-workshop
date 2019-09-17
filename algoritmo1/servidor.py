#!/usr/bin/env python3
import socket, sys
from collections import defaultdict
from comandos import *


TAM_PAYLOAD = 512 # tamanho do payload

# Chaves secretas utilizadas para criptografia simétrica
CHAVES_SECRETAS = {"Alice":b'WRprQNey0P5VH1JoCcMW-2PW6GZjKxIq6unPLF8QCG8=',
                  "Bob":b'wqC0d_A0tbZPlFlAdHbAupEXyqkGSbJcoppU28tzA_g='}


if len(sys.argv) < 2:
    print(f"[+] Utilização: {sys.argv[0].lstrip('./')} <porta>")
    print("[+] <porta> : Porta da rede na qual o servidor vai operar")
    raise SystemExit

try:
    PORTA = int(sys.argv[1])
except ValueError:
    print("[+] Por favor utilize somente números inteiros para a porta.")
    raise SystemExit


def main():
    grupos = {'G1':['Alice', 'Bob']}
    mensagens_pendentes = defaultdict(list) # Estrutura para armazenar as mensagens pendentes

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Impede que o socket fique ocupado após a execução
    sock.bind((socket.gethostname(), PORTA)) # Define endereço e porta do socket
    sock.listen() # Aguarda conexões no endereço especificado

    while True:
        nonce_servidor = 0
        cliente, endereco = sock.accept() # Aceita solicitações de conexão
        print(f"[+] Conexão com {endereco} estabelecida.\n")
        id_cliente = remover_padding(cliente.recv(TAM_PAYLOAD)) # Identifica o ID do cliente que conectou-se
        cliente.send(bytes(adicionar_padding(f"[+] Conexão estabelecida. Bem-vindo {id_cliente}! \n"), 'utf-8'))
        msg_pendentes = verifica_pendentes(id_cliente, mensagens_pendentes) # Verifica se há mensagens pendentes

        if len(msg_pendentes) > 0:
            notify(cliente, nonce_servidor, msg_pendentes, CHAVES_SECRETAS[id_cliente])
        else:
            cliente.send(bytes(adicionar_padding("[+] Você não tem mensagens pendentes. \n"), 'utf-8'))

        payload = cliente.recv(TAM_PAYLOAD)
        tratar_cliente(cliente, id_cliente, CHAVES_SECRETAS[id_cliente], payload, grupos, mensagens_pendentes, nonce_servidor)
        print(f"[+] Conexão com {id_cliente} {endereco} encerrada.\n")
        cliente.close()
main()
