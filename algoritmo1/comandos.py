import hmac, hashlib, socket
from cryptography.fernet import Fernet

TAM_PAYLOAD = 512

def criptografar(mensagem, chave):
    mecanismo = Fernet(chave)
    return mecanismo.encrypt((mensagem).encode())

def decodificar(mensagem, chave, comando):
    mecanismo = Fernet(chave)
    mensagem = mecanismo.decrypt(mensagem.encode()).decode()
    if comando == 'PUT' or comando == 'GTA':
        grupo = mensagem[:2]
        return grupo, mensagem[2:]
    elif comando == 'PTA' or comando == 'NTF':
        return '', mensagem
    elif comando == 'GET':
        return mensagem, ''


def verificar_hmac(payload, chave):
    payload = remover_padding(payload)
    msg_hmac = payload[-64:] # Os últimos 64 caracteres do payload são o HMAC
    dados = payload[:-64]
    h = hmac.new(chave, dados.encode(), hashlib.sha256)
    if h.hexdigest() == msg_hmac:
        return 'OK'
    else:
        return 'NOK'


def gerar_hmac(chave, info):
    h = hmac.new(chave, info.encode(), hashlib.sha256)
    return h.hexdigest()


def adicionar_padding(mensagem):
    encoded_size = len(bytes(mensagem.encode()))
    padding = (TAM_PAYLOAD - encoded_size + len(mensagem))
    # Preenche o final da mensagem com espaços vazios
    return mensagem.ljust(padding, ' ')


def remover_padding(mensagem):
    # Remove o preenchimento ao final da mensagem
    return mensagem.decode().rstrip(' ')


def put(destino, nonce, grupo, mensagem, chave):
    payload = ''
    payload += "PUT" + '/' # Comando PUT
    payload += str(nonce) + '/'
    msg_criptografada = criptografar(grupo + mensagem, chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += msg_criptografada.decode() + '/'
    payload += gerar_hmac(chave, payload) # Adiciona um HMAC ao payload para ajudar a verificar a integridade dos dados
    payload = adicionar_padding(payload) # Preenche o restante do espaço do payload com espaços vazios
    destino.send(bytes(payload, 'utf-8'))
    nonce += 1
    print(f"[+] Mensagem publicada: ({grupo}) {mensagem}")
    return


def put_ack(destino, nonce, chave):
    payload = ''
    payload += "PTA" + '/' # Comando PUT_ACK
    payload += str(nonce) + '/'
    msg_criptografada = criptografar(f"[+] Mensagem (Nonce: {nonce}) entregue!\n", chave)
    payload += msg_criptografada.decode() + '/'
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(payload, 'utf-8'))
    return


def extrair_dados(payload, chave):
    if verificar_hmac(payload, chave) == 'NOK': # Verifica a integridade da mensagem
        print("[+] HMAC incompatível com a mensagem recebida.")
        raise SystemExit
    payload = remover_padding(payload)
    comando, nonce, msg_criptografada, hmac = payload.split('/')
    grupo, mensagem = decodificar(msg_criptografada, chave, comando)
    return comando, int(nonce), grupo, mensagem


def get(destino, nonce, grupo, chave):
    payload = ''
    payload += "GET" + '/' # Comando GET
    payload += str(nonce) + '/'
    msg_criptografada = criptografar(grupo, chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += msg_criptografada.decode() + '/'
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(payload, 'utf-8'))
    return


def get_ack(destino, nonce, mensagem, grupo, chave):
    payload = ''
    payload += "GTA" + '/' # Comando PUT_ACK
    payload += str(nonce) + '/'
    msg_criptografada = criptografar(grupo + mensagem, chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += msg_criptografada.decode() + '/'
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(payload, 'utf-8'))
    return


def notify(destino, nonce, lista_grupos, chave):
    payload = ''
    payload += "NTF" + '/' # Comando NOTIFY
    payload += str(nonce) + '/'
    msg_criptografada = criptografar("[+] Mensagens pendentes nos grupos: " + ','.join(lista_grupos), chave) # Criptografa os dados da mensagem usando a chave secreta
    payload += msg_criptografada.decode() + '/'
    payload += gerar_hmac(chave, payload)
    destino.send(bytes(payload, 'utf-8'))
    return

def conectar(PORTA, ID_CLIENTE):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Instancia um socket
    try:
        sock.connect((socket.gethostname(), PORTA)) # Conecta com o servidor na porta 5555
        sock.send(bytes(adicionar_padding(ID_CLIENTE), 'utf-8')) # Informa o ID do cliente
    except ConnectionError:
        print("[+] Erro na conexão com o servidor.")
        raise SystemExit
    return sock


def publicar_mensagem(sock, nonce, grupo, mensagem, chave):
    put(sock, nonce, 'G1', 'Olá grupo!', chave) # Publica uma mensagem
    resposta = sock.recv(TAM_PAYLOAD)
    comando, nonce_recebido, grupo, mensagem = extrair_dados(resposta, chave)

    if nonce_recebido != nonce:
        print("[+] Erro na sincronia das mensagens.")

    if comando == 'PTA': # Recebeu um ACK do servidor
        nonce += 1 # Após receber a confirmação do servidor, incrementa o nonce
        print(f"{mensagem}")

    return


def recuperar_mensagem(sock, nonce, grupo, chave):
    get(sock, nonce, grupo, chave)
    print("[+] Solicitando mensagens... \n")
    resposta = sock.recv(TAM_PAYLOAD)
    comando, nonce_recebido, grupo, mensagem = extrair_dados(resposta, chave)

    if nonce_recebido != nonce:
        print("[+] Erro na sincronia das mensagens.")

    if comando == 'GTA': # Recebeu um GET_ACK do servidor
        nonce += 1 # Após receber a confirmação do servidor, incrementa o nonce
        print(f"[+] Mensagem recebida:\n\t{mensagem}")

    return
