#!/usr/bin/env python3
import math, sys, random, hkdf, socket, base64
from comandos import *

TAM_PAYLOAD = 512

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
