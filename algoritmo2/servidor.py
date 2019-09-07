#!/usr/bin/env python3
import socket, sys
from collections import defaultdict
from comandos import *

''' Algoritmo 3:
    Geração e atualização de chaves secretas de sessão '''

TAM_PAYLOAD = 512 # tamanho do payload

# Chaves secretas utilizadas para criptografia simétrica
CHAVES_SECRETAS = {"cliente1":None,
                  "cliente2":None}


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
    grupos = {'G1':['cliente1', 'cliente2']}
    mensagens_pendentes = defaultdict(list) # Estrutura para armazenar as mensagens pendentes

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Impede que o socket fique ocupado após a execução
    sock.bind((socket.gethostname(), PORTA)) # Define endereço e porta do socket
    sock.listen() # Aguarda conexões no endereço especificado

    while True:
        nonce_servidor = 0
        cliente, endereco = sock.accept() # Aceita solicitações de conexão
        print(f"[+] Conexão com {endereco} estabelecida.\n")

        chave_longa_duracao = responder_diffie_hellman(cliente) # Gera uma chave para a comunicação com o cliente
        id_cliente = remover_padding(cliente.recv(TAM_PAYLOAD)) # Identifica o ID do cliente que conectou-se
        CHAVES_SECRETAS[id_cliente] = chave_longa_duracao # Armazena a chave gerada para a comunicação com o cliente

        cliente.send(bytes(adicionar_padding(f"[+] Conexão estabelecida. Bem-vindo {id_cliente}! \n"), 'utf-8'))
        msg_pendentes = verifica_pendentes(id_cliente, mensagens_pendentes) # Verifica se há mensagens pendentes

        if len(msg_pendentes) > 0:
            notify(cliente, nonce_servidor, msg_pendentes, CHAVES_SECRETAS[id_cliente])

        else:
            cliente.send(bytes(adicionar_padding("[+] Você não tem mensagens pendentes. \n"), 'utf-8'))

        print("[+] Informação sobre mensagens pendentes enviadas para {}\n".format(id_cliente))

        chave_longa_duracao = atualizar_chave(chave_longa_duracao)
        CHAVES_SECRETAS[id_cliente] = chave_longa_duracao # Armazena a chave gerada para a comunicação com o cliente

        payload = cliente.recv(TAM_PAYLOAD)
        tratar_cliente(cliente, id_cliente, CHAVES_SECRETAS[id_cliente], payload, grupos, mensagens_pendentes, nonce_servidor)
        print(f"[+] Conexão com {id_cliente} {endereco} encerrada.\n")
        cliente.close()
main()
