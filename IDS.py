import socket
import time
from collections import defaultdict, deque
import os

# Cria um socket raw para escutar pacotes IPv4
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# '''
# Extraindo o IP de origem do pacote TCP
# '''
# def get_ip(pacote):
#     ip_cabecalho = pacote[0:20]  # Cabeçalho IP
#     ip_origem = socket.inet_ntoa(ip_cabecalho[12:16])
#     return ip_origem

# '''
# Checa se o pacote é TCP e o flag SYN está ativado
# '''
# def is_pacote_syn(pacote):
#     tcp_cabecalho = pacote[20:40]  # Cabeçalho TCP
#     flags = tcp_cabecalho[13]  # Byte de flags TCP
#     syn_flag = flags & 0x02  # SYN flag é o segundo bit (0x02)
#     return True if syn_flag > 0 else False

def monitorar_pacotes():
    while True:
        # Recebe dados do socket
        pacote, endereco = sock.recvfrom(65565)
        
        # Extraindo informações do pacote TCP
        ip_cabecalho = pacote[0:20]  # Cabeçalho IP
        ip_origem = socket.inet_ntoa(ip_cabecalho[12:16])
        
        # Checa se o pacote é TCP e o flag SYN está ativado
        tcp_cabecalho = pacote[20:40]  # Cabeçalho TCP
        flags = tcp_cabecalho[13]  # Byte de flags TCP
        syn_flag = flags & 0x02  # SYN flag é o segundo bit (0x02)
        
        if syn_flag:
            processar_pacote_syn(ip_origem)

# Armazena o número de SYNs recebidos por IP
contadores_syn = defaultdict(list)
intervalo_tempo = 1  # 1 segundo para resetar a contagem
threshold_ms = 50  # Limiar para detectar ataque
# defaultdict(lambda: deque(maxlen=2))

def processar_pacote_syn(ip_origem):
    print("processando pacote de", ip_origem)
    agora = int(time.time_ns() / 1e6)
    
    print(f"{ip_origem} tem {len(contadores_syn[ip_origem])} ocorrências no buffer | avg: {media_timestamps(contadores_syn[ip_origem])}")
    # Incrementa contador para o IP
    contadores_syn[ip_origem].append(agora)

    # print(media_timestamps(contadores_syn[ip_origem]))
    
    # Verifica se o número de SYNs excede o limite estabelecido
    if media_timestamps(contadores_syn[ip_origem]) < threshold_ms:
        print(ip_origem, "excedeu o limite de requisições e está sendo bloqueado")
        bloquear_ip(ip_origem)
        registrar_log(ip_origem)
        # Reseta o contador para o IP
        contadores_syn[ip_origem].clear() #limpa a lista de controle

def bloquear_ip(ip):
    # Executa comando para bloquear o IP usando iptables
    os.system(f"iptables -A INPUT -s {ip} -j DROP")

def registrar_log(ip):
    with open("log_syn_flood.txt", "a") as log_file:
        log_file.write(f"{time.ctime()}: Bloqueio de IP {ip} por possível SYN flood | avg: \n")

# def registrar_ip_bloqueado(ip):
#     ips_bloqueados[ip].append(ip)


def media_timestamps(list_timestamps):
    list_delta_t = []
    for i in range(0, len(list_timestamps)-1):
        delta_t = list_timestamps[i+1] - list_timestamps[i]
        list_delta_t.append(delta_t)
    if (len(list_timestamps) >= 2):
        return sum(list_delta_t)/len(list_delta_t)
    else:
        return 0

monitorar_pacotes()