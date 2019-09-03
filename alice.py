#!/usr/bin/env python3
import socket, hashlib, sys
from comandos import *

''' Algoritmo 6:
    Recuperação de chaves utilizando criptografia simétrica '''

TAM_PAYLOAD = 512

# Chaves necessárias para a geração do idvv
chave_mestra = b'D-CrwG96Kd77AcpaEmOH8wzV2e30ufvE0wmQOjjX2r8='
chave_idvv = b'aXMcM_1Iy4SzxJ1snXXnYxlgVkz3c3tdfMcULEI6wCY='
semente_idvv = b'HXddsdFmrcLSQl-BtApr7tJsQ3U0TkPfOgxSjaX0phI='


def main(chave_idvv, semente_idvv, chave_mestra, porta):
    k_rec, random = computar_chave_rec(semente_idvv, chave_idvv, chave_mestra)
    bob = conectar(porta) # Estabelece conexão com Bob
    nonce = 0

    rec(bob, 0, random, chave_mestra) # Envia o comando REC para Bob
    print("[+] Solicitação de recuperação de chave enviada para Bob.\n")
    resposta = bob.recv(TAM_PAYLOAD)
    comando, nonce_recebido, dados = extrair_dados(resposta, chave_mestra)
    if comando == 'RCA': # Comando REC_ACK
        check_nonce(nonce, nonce_recebido) # Verifica a sincronia das mensagens

    nonce += 1
    k_css = hashlib.sha256(k_rec.encode()).hexdigest().encode()
    print("[+] Nova chave secreta de sessão gerada com sucesso: {}\n".format(k_css))

    # Deriva uma chave que possa ser usada pelo algoritmo de criptografia a partir de k_css
    k_css = derivar_chave(k_css)

    key(bob, nonce, nonce_recebido, k_css) # Avisa Bob que a chave foi atualizada com sucesso

    mensagem = bob.recv(TAM_PAYLOAD)
    comando, nonce_recebido, dados = extrair_dados(mensagem, k_css)
    check_nonce(nonce, nonce_recebido) # Verifica a sincronia das mensagens

    if comando == 'KEY':
        print("[+] Bob gerou uma nova chave secreta com sucesso.\n")

    print("[+] Fim do processo de recuperação de chaves.")

    bob.close()


if len(sys.argv) < 2:
    print(f"[+] Utilização: {sys.argv[0].lstrip('./')} <porta>")
    print("[+] <porta> : Porta da rede na qual o outro cliente está operando")
    raise SystemExit

try:
    porta = int(sys.argv[1])
except ValueError:
    print("[+] Por favor utilize somente números inteiros para a porta.")
    raise SystemExit

main(semente_idvv, chave_idvv, chave_mestra, porta)
