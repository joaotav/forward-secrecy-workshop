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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Impede que o socket fique ocupado após a execução
    sock.bind((socket.gethostname(), porta))
    sock.listen(5)

    while True:
        nonce = 0
        cliente, endereco = sock.accept()
        print(f"[+] Conexão com {endereco} estabelecida.\n")
        mensagem = cliente.recv(TAM_PAYLOAD) # Recebe mensagem de Alice
        comando, nonce_recebido, dados = extrair_dados(mensagem, chave_mestra)
        check_nonce(nonce, nonce_recebido) # Verifica a sincronia das mensagens

        if comando == 'REC': # Se recebeu o comando REC, gera uma chave de recuperação.
            print("[+] Alice solicitou a recuperação da chave.\n")

            rec_ack(cliente, nonce, nonce_recebido, chave_mestra)
            nonce += 1
            k_rec, random = computar_chave_rec(semente_idvv, chave_idvv, chave_mestra)

            # Computa uma nova chave secreta de sessão
            k_css = hashlib.sha256(k_rec.encode()).hexdigest().encode()
            print("[+] Nova chave secreta de sessão gerada com sucesso: {}\n".format(k_css))

        # Deriva uma chave que possa ser usada pelo algoritmo de criptografia a partir de k_css
        k_css = derivar_chave(k_css)

        mensagem = cliente.recv(TAM_PAYLOAD) # Recebe mensagem de Alice
        comando, nonce_recebido, dados = extrair_dados(mensagem, k_css)
        check_nonce(nonce, nonce_recebido) # Verifica a sincronia das mensagens

        if comando == 'KEY': # Se recebeu o comando key
            print("[+] Alice gerou uma nova chave secreta com sucesso.\n")
            key(cliente, nonce, nonce_recebido, k_css) # Avisa Alice que a nova chave também foi gerada com sucesso

        print("[+] Fim do processo de recuperação de chaves.")
        break

    sock.close()


if len(sys.argv) < 2:
    print(f"[+] Utilização: {sys.argv[0].lstrip('./')} <porta>")
    print("[+] <porta> : Porta da rede na qual o cliente irá aceitar conexões.")
    raise SystemExit

try:
    porta = int(sys.argv[1])
except ValueError:
    print("[+] Por favor utilize somente números inteiros para a porta.")
    raise SystemExit

main(semente_idvv, chave_idvv, chave_mestra, porta)
