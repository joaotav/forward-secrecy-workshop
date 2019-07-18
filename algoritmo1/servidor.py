#!/usr/bin/env python3
import socket, sys
from collections import defaultdict
from comandos import *

def tratar_cliente(socket_cliente, id_cliente, chave, payload, grupos, mensagens_pendentes, nonce_esperado):
    comando, nonce_recebido, grupo, mensagem = extrair_dados(payload, chave)

    if nonce_recebido != nonce_esperado: # Verifica se as mensagens estão na sequência correta
        print("[+] Erro na sincronia das mensagens. \n")
        return

    if comando == 'PUT': # O cliente deseja publicar uma mensagem
        print(f"[+] Requisição de publicação de mensagem recebida de: {id_cliente}\n")
        print(f"[+] Grupo: {grupo} | Mensagem: {mensagem} \n")
        if grupo in grupos: # Se o grupo existe
            if id_cliente in grupos[grupo]: # Se o cliente que enviou a mensagem está no grupo
                for cliente in grupos[grupo]:
                    if cliente != id_cliente: # Envia a mensagem para os outros clientes
                        mensagens_pendentes[cliente].append('(' + grupo + ') ' + id_cliente + ': ' + mensagem + '\n')
                        print("[+] Mensagem publicada.\n")
                        put_ack(socket_cliente, nonce_recebido, chave)
                        nonce_esperado += 1

    elif comando == 'GET': # O cliente deseja recuperar mensagens
        print(f"[+] Requisição de recuperação de mensagem recebida de: {id_cliente}\n")
        for cliente in mensagens_pendentes:
            if cliente == id_cliente:
                if cliente in mensagens_pendentes.keys() and len(mensagens_pendentes[cliente]) > 0:
                    for mensagem in mensagens_pendentes[cliente]:
                        if mensagem[1:3] == grupo: # Se a mensagem corresponde ao grupo solicitado
                            get_ack(socket_cliente, nonce_recebido, mensagem, grupo, chave)
                            print(f"[+] Mensagens pendentes enviadas para {id_cliente}\n")
                            nonce_esperado += 1
                            break
                else:
                    print("[+] Não há mensagens pendentes. \n")


def verifica_pendentes(id_cliente, mensagens_pendentes):
    lista_grupos = []
    for cliente in mensagens_pendentes:
        if cliente == id_cliente: # Verifica as mensagens do cliente em questão
            if cliente in mensagens_pendentes.keys() and len(mensagens_pendentes[cliente]) > 0: # Se há mensagens pendentes
                for mensagem in mensagens_pendentes[cliente]: # Para cada mensagem recebida
                    if mensagem[:4] not in lista_grupos: # Se ainda não há notificação sobre o grupo
                        lista_grupos.append(mensagem[:4]) # Adiciona uma notificação sobre o grupo
    return lista_grupos


TAM_PAYLOAD = 512 # tamanho do payload

# Chaves secretas utilizadas para criptografia simétrica
CHAVES_SECRETAS = {"cliente1":b'WRprQNey0P5VH1JoCcMW-2PW6GZjKxIq6unPLF8QCG8=',
                  "cliente2":b'wqC0d_A0tbZPlFlAdHbAupEXyqkGSbJcoppU28tzA_g='}


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
