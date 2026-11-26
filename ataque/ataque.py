"""
Simulação do ataque: um agente interno com a credencial válida de um operador
emite ordens de transferência em sequência até ser interrompido ou esgotar
o número de tentativas.

O parâmetro --dispositivo define de qual "máquina" o ataque parte:
    nenhum             -> computador do criminoso, sem certificado do laboratório
    estacao-operador2  -> estação de outro funcionário (o próprio agente interno)
    estacao-operador1  -> estação autorizada do operador dono da credencial

Uso (na pasta do laboratório):
    python ataque/ataque.py
    python ataque/ataque.py --dispositivo nenhum
    python ataque/ataque.py --dispositivo estacao-operador2
    python ataque/ataque.py --dispositivo estacao-operador1 --quantidade 20
"""
import argparse
import csv
import os
import sys
import time
from datetime import datetime

import requests

PASTA_LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PASTA_CERTS = os.path.join(PASTA_LAB, "certs")
PASTA_RESULTADOS = os.path.join(PASTA_LAB, "resultados")
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/tcc/protocol/openid-connect/token"
GATEWAY_URL = "https://localhost:8443"
CA_CERT = os.path.join(PASTA_CERTS, "ca.crt")
DISPOSITIVO_EXPERIMENTADOR = "estacao-operador1"  # usado só para zerar o saldo entre execuções


def certificado(dispositivo: str):
    """Par (certificado, chave) da estação, ou None se o ataque parte de máquina sem certificado."""
    if dispositivo == "nenhum":
        return None
    crt = os.path.join(PASTA_CERTS, f"{dispositivo}.crt")
    key = os.path.join(PASTA_CERTS, f"{dispositivo}.key")
    if not os.path.exists(crt):
        print(f"Certificado {crt} não encontrado. Rode: docker compose up -d --force-recreate certgen")
        sys.exit(1)
    return (crt, key)


def obter_token(usuario: str, senha: str) -> str:
    """Faz login no Keycloak com usuário e senha (o que o atacante comprou)."""
    for _ in range(40):
        try:
            r = requests.post(KEYCLOAK_TOKEN_URL, data={
                "grant_type": "password", "client_id": "operador-cli",
                "username": usuario, "password": senha,
            }, timeout=5)
            if r.status_code == 200:
                return r.json()["access_token"]
            if r.status_code == 404:  # realm ainda sendo importado
                time.sleep(3)
                continue
            print(f"Login recusado: {r.status_code} {r.text}")
            sys.exit(1)
        except requests.ConnectionError:
            print("Aguardando o Keycloak subir...")
            time.sleep(3)
    print("Keycloak não respondeu.")
    sys.exit(1)


def zerar_saldo():
    """Restaura o saldo da conta reserva antes do experimento (papel do experimentador, não do atacante)."""
    try:
        requests.post(f"{GATEWAY_URL}/reset", verify=CA_CERT,
                      cert=certificado(DISPOSITIVO_EXPERIMENTADOR), timeout=10)
    except requests.RequestException as e:
        print(f"Aviso: não foi possível zerar o saldo ({e.__class__.__name__}).")


def motivo_da_resposta(r: requests.Response) -> str:
    try:
        corpo = r.json()
        return corpo.get("motivo", corpo.get("detail", ""))
    except ValueError:
        return r.text[:120]


def formatar_reais(v: float) -> str:
    return f"R$ {v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def main():
    p = argparse.ArgumentParser(description="Simulação de ataque com credencial válida")
    p.add_argument("--usuario", default="operador1")
    p.add_argument("--senha", default="Senha@123")
    p.add_argument("--dispositivo", default="estacao-operador1",
                   help="nenhum | estacao-operador1 | estacao-operador2")
    p.add_argument("--quantidade", type=int, default=166, help="número de ordens de transferência")
    p.add_argument("--valor", type=float, default=3_000_000, help="valor de cada ordem (R$)")
    p.add_argument("--intervalo", type=float, default=0.05, help="pausa entre ordens (s)")
    p.add_argument("--parar-apos-negacoes", type=int, default=5,
                   help="encerra após N negações seguidas (o atacante desiste)")
    a = p.parse_args()

    zerar_saldo()

    sessao = requests.Session()
    sessao.verify = CA_CERT
    sessao.cert = certificado(a.dispositivo)
    sessao.headers["Authorization"] = f"Bearer {obter_token(a.usuario, a.senha)}"

    inicio = time.perf_counter()
    aceitas, negadas_seguidas, total = 0, 0, 0.0
    linhas = []

    for i in range(1, a.quantidade + 1):
        try:
            r = sessao.post(f"{GATEWAY_URL}/transferencias",
                            json={"valor": a.valor, "destino": f"conta-laranja-{i % 7}"})
            status, motivo = r.status_code, motivo_da_resposta(r)
        except requests.exceptions.SSLError as e:
            status, motivo = 0, f"conexão TLS recusada: {e.__class__.__name__}"
        decorrido = round(time.perf_counter() - inicio, 3)

        if status == 201:
            aceitas += 1
            total += a.valor
            negadas_seguidas = 0
        else:
            negadas_seguidas += 1
        linhas.append({"ordem": i, "usuario": a.usuario, "dispositivo": a.dispositivo,
                       "status": status, "motivo": motivo,
                       "total_transferido": total, "tempo_s": decorrido})

        if negadas_seguidas >= a.parar_apos_negacoes:
            print(f"Ataque interrompido na ordem {i}: {motivo}")
            break
        time.sleep(a.intervalo)

    os.makedirs(PASTA_RESULTADOS, exist_ok=True)
    arquivo = os.path.join(PASTA_RESULTADOS,
                           f"ataque_{a.dispositivo}_{datetime.now():%Y%m%d_%H%M%S}.csv")
    with open(arquivo, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=linhas[0].keys())
        w.writeheader()
        w.writerows(linhas)

    print("\n===== RESULTADO DO ATAQUE =====")
    print(f"Credencial usada:     {a.usuario}")
    print(f"Dispositivo:          {a.dispositivo}")
    print(f"Ordens enviadas:      {len(linhas)}")
    print(f"Ordens aceitas:       {aceitas}")
    print(f"Valor transferido:    {formatar_reais(total)}")
    print(f"Duração:              {linhas[-1]['tempo_s']} s")
    print(f"Detalhes salvos em:   resultados/{os.path.basename(arquivo)}")


if __name__ == "__main__":
    main()
