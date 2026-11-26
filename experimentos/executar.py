"""
Execução oficial dos experimentos do TCC.

Roda todos os cenários de ataque e de uso legítimo, várias vezes cada,
trocando automaticamente o modo do laboratório (perímetro / zero trust) e o
horário simulado. Ao final, chama a análise, que gera tabelas e gráficos.

Uso (na pasta do laboratório, com o ambiente no ar):
    python experimentos/executar.py
    python experimentos/executar.py --repeticoes 3

Saída: resultados/experimento_<data>/
    execucoes.csv   todas as ordens de todas as execuções
    metadados.json  parâmetros do experimento (limites, repetições, data)
    + tabelas e gráficos gerados por analise.py
"""
import argparse
import csv
import json
import math
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

PASTA_LAB = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PASTA_CERTS = os.path.join(PASTA_LAB, "certs")
CA_CERT = os.path.join(PASTA_CERTS, "ca.crt")
GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost:8443")
TOKEN_URL = "http://localhost:8080/realms/tcc/protocol/openid-connect/token"
SENHAS = {"operador1": "Senha@123", "operador2": "Senha@456"}
ESTACAO_DE = {"operador1": "estacao-operador1", "operador2": "estacao-operador2"}

# ---------------------------------------------------------------------------
# Cenários
# ---------------------------------------------------------------------------
# Ataques: a credencial do operador1 é usada para emitir ordens em sequência.
# Uso legítimo: operador1 e operador2, cada um na própria estação, em horário
# comercial, com valores variados (perfil usado para medir falsos positivos).
CENARIOS = [
    {"id": "C1", "nome": "Perímetro: credencial válida", "tipo": "ataque",
     "modo": "perimetro", "hora": "", "dispositivo": "nenhum", "valor": 3_000_000, "quantidade": 166},
    {"id": "L1", "nome": "Perímetro: uso legítimo", "tipo": "legitimo",
     "modo": "perimetro", "hora": "", "quantidade": 30},
    {"id": "C2", "nome": "ZT: computador sem certificado", "tipo": "ataque",
     "modo": "zero_trust", "hora": "03:00", "dispositivo": "nenhum", "valor": 3_000_000, "quantidade": 166},
    {"id": "C3", "nome": "ZT: estação de outro operador", "tipo": "ataque",
     "modo": "zero_trust", "hora": "03:00", "dispositivo": "estacao-operador2", "valor": 3_000_000, "quantidade": 166},
    {"id": "C4", "nome": "ZT: estação autorizada, madrugada", "tipo": "ataque",
     "modo": "zero_trust", "hora": "03:00", "dispositivo": "estacao-operador1", "valor": 3_000_000, "quantidade": 166},
    {"id": "C5", "nome": "ZT: ataque discreto, horário comercial", "tipo": "ataque",
     "modo": "zero_trust", "hora": "10:00", "dispositivo": "estacao-operador1", "valor": 900_000, "quantidade": 166},
    {"id": "L2", "nome": "ZT: uso legítimo", "tipo": "legitimo",
     "modo": "zero_trust", "hora": "10:00", "quantidade": 30},
]

NEGACOES_PARA_DESISTIR = 5   # o atacante desiste após N negações seguidas
VALOR_LEGITIMO_MIN, VALOR_LEGITIMO_MAX = 10_000, 400_000

CAMPOS = ["cenario", "nome_cenario", "tipo", "modo", "hora_simulada", "repeticao", "ordem",
          "usuario", "dispositivo", "valor", "status", "aceita", "motivo",
          "total_transferido", "tempo_s", "latencia_ms"]


# ---------------------------------------------------------------------------
# Infraestrutura
# ---------------------------------------------------------------------------
def certificado(dispositivo: str):
    if dispositivo == "nenhum":
        return None
    return (os.path.join(PASTA_CERTS, f"{dispositivo}.crt"),
            os.path.join(PASTA_CERTS, f"{dispositivo}.key"))


def nova_sessao(dispositivo: str, token: str | None = None) -> requests.Session:
    s = requests.Session()
    s.verify = CA_CERT
    s.cert = certificado(dispositivo)
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def obter_token(usuario: str) -> str:
    for _ in range(40):
        try:
            r = requests.post(TOKEN_URL, data={"grant_type": "password", "client_id": "operador-cli",
                                               "username": usuario, "password": SENHAS[usuario]}, timeout=5)
            if r.status_code == 200:
                return r.json()["access_token"]
            time.sleep(2)
        except requests.ConnectionError:
            time.sleep(3)
    sys.exit(f"Não foi possível obter token para {usuario}.")


def configurar_laboratorio(modo: str, hora: str):
    """Recria gateway e Nginx com o modo e o horário do cenário e espera ficarem prontos."""
    print(f"\n>> Configurando laboratório: MODO={modo} HORA_SIMULADA={hora or '(real)'}")
    env = {**os.environ, "MODO": modo, "HORA_SIMULADA": hora}
    subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "gateway", "nginx"],
                   cwd=PASTA_LAB, env=env, check=True, capture_output=True)
    sessao = nova_sessao("estacao-operador1")
    for _ in range(60):
        try:
            r = sessao.get(f"{GATEWAY_URL}/saude", timeout=3)
            if r.ok and r.json().get("modo") == modo:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    sys.exit("O gateway não ficou pronto após a reconfiguração.")


def preparar_execucao():
    """Zera saldo, histórico e bloqueios (papel do experimentador)."""
    nova_sessao("estacao-operador1").post(f"{GATEWAY_URL}/reset", timeout=15)


def enviar_ordem(sessao: requests.Session, valor: float, destino: str) -> tuple[int, str, float]:
    inicio = time.perf_counter()
    try:
        r = sessao.post(f"{GATEWAY_URL}/transferencias", json={"valor": valor, "destino": destino}, timeout=15)
        status = r.status_code
        try:
            corpo = r.json()
            motivo = corpo.get("motivo", corpo.get("detail", ""))
        except ValueError:
            motivo = r.text[:120]
    except requests.exceptions.SSLError as e:
        status, motivo = 0, f"conexão TLS recusada: {e.__class__.__name__}"
    return status, motivo, round((time.perf_counter() - inicio) * 1000, 2)


# ---------------------------------------------------------------------------
# Execuções
# ---------------------------------------------------------------------------
def executar_ataque(c: dict, rep: int) -> list[dict]:
    preparar_execucao()
    sessao = nova_sessao(c["dispositivo"], obter_token("operador1"))
    linhas, total, negadas, t0 = [], 0.0, 0, time.perf_counter()
    for i in range(1, c["quantidade"] + 1):
        status, motivo, lat = enviar_ordem(sessao, c["valor"], f"conta-laranja-{i % 7}")
        aceita = status == 201
        total += c["valor"] if aceita else 0
        negadas = 0 if aceita else negadas + 1
        linhas.append({"ordem": i, "usuario": "operador1", "dispositivo": c["dispositivo"],
                       "valor": c["valor"], "status": status, "aceita": int(aceita), "motivo": motivo,
                       "total_transferido": total, "tempo_s": round(time.perf_counter() - t0, 3),
                       "latencia_ms": lat})
        if negadas >= NEGACOES_PARA_DESISTIR:
            break
    return linhas


def executar_legitimo(c: dict, rep: int) -> list[dict]:
    preparar_execucao()
    rng = random.Random(1000 + rep)   # semente fixa: mesmas ordens nos dois modos
    sessoes = {u: nova_sessao(ESTACAO_DE[u], obter_token(u)) for u in ("operador1", "operador2")}
    linhas, total, t0 = [], 0.0, time.perf_counter()
    for i in range(1, c["quantidade"] + 1):
        usuario = "operador1" if i % 2 else "operador2"
        valor = round(math.exp(rng.uniform(math.log(VALOR_LEGITIMO_MIN), math.log(VALOR_LEGITIMO_MAX))), 2)
        status, motivo, lat = enviar_ordem(sessoes[usuario], valor, f"fornecedor-{rng.randint(1, 20)}")
        aceita = status == 201
        total += valor if aceita else 0
        linhas.append({"ordem": i, "usuario": usuario, "dispositivo": ESTACAO_DE[usuario],
                       "valor": valor, "status": status, "aceita": int(aceita), "motivo": motivo,
                       "total_transferido": total, "tempo_s": round(time.perf_counter() - t0, 3),
                       "latencia_ms": lat})
    return linhas


def main():
    p = argparse.ArgumentParser(description="Executa os experimentos oficiais do TCC")
    p.add_argument("--repeticoes", type=int, default=5)
    a = p.parse_args()

    pasta = os.path.join(PASTA_LAB, "resultados", f"experimento_{datetime.now():%Y%m%d_%H%M%S}")
    os.makedirs(pasta, exist_ok=True)
    with open(os.path.join(PASTA_LAB, "opa", "data.json"), encoding="utf-8") as f:
        limites = json.load(f)["limites"]
    metadados = {"inicio_utc": datetime.now(timezone.utc).isoformat(), "repeticoes": a.repeticoes,
                 "cenarios": CENARIOS, "limites": limites,
                 "negacoes_para_desistir": NEGACOES_PARA_DESISTIR,
                 "valor_legitimo_faixa": [VALOR_LEGITIMO_MIN, VALOR_LEGITIMO_MAX]}

    arquivo = os.path.join(pasta, "execucoes.csv")
    with open(arquivo, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS)
        w.writeheader()
        config_atual = None
        for c in CENARIOS:
            config = (c["modo"], c["hora"])
            if config != config_atual:
                configurar_laboratorio(*config)
                config_atual = config
            for rep in range(1, a.repeticoes + 1):
                linhas = executar_ataque(c, rep) if c["tipo"] == "ataque" else executar_legitimo(c, rep)
                for ln in linhas:
                    w.writerow({"cenario": c["id"], "nome_cenario": c["nome"], "tipo": c["tipo"],
                                "modo": c["modo"], "hora_simulada": c["hora"] or "real",
                                "repeticao": rep, **ln})
                f.flush()
                aceitas = sum(ln["aceita"] for ln in linhas)
                print(f"   {c['id']} rep {rep}: {aceitas}/{len(linhas)} aceitas, "
                      f"R$ {linhas[-1]['total_transferido']:,.0f}")

    metadados["fim_utc"] = datetime.now(timezone.utc).isoformat()
    with open(os.path.join(pasta, "metadados.json"), "w", encoding="utf-8") as f:
        json.dump(metadados, f, ensure_ascii=False, indent=2)

    # Deixa o laboratório no modo zero trust, horário real
    configurar_laboratorio("zero_trust", "")

    print(f"\nExperimento concluído. Dados em: {os.path.relpath(pasta, PASTA_LAB)}")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import analise
    analise.gerar(pasta)


if __name__ == "__main__":
    main()
