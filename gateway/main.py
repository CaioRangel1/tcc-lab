"""
Gateway: ponto de aplicação de políticas (PEP).

Todas as requisições à API de transferências passam por aqui.

Modo "perimetro":
    verifica apenas se o token emitido pelo Keycloak é válido. Uma credencial
    válida é suficiente para operar, como em uma arquitetura baseada em perímetro.

Modo "zero_trust":
    controle 1 - vinculação ao dispositivo: o Nginx exige o certificado da estação
    (mTLS) e o gateway confere se essa estação é a autorizada para o operador do
    token, segundo o inventário de dispositivos.
    controle 2 - autorização contextual: a cada ordem, o gateway envia ao OPA o
    valor, o histórico recente do operador e o horário, e aplica a decisão.
    Após negações sucessivas, o operador é bloqueado (sessão revogada e conta
    desativada no Keycloak), interrompendo o fluxo de transações.

Cada decisão é registrada em /data/eventos.csv para a análise dos resultados.
"""
import csv
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

MODO = os.getenv("MODO", "perimetro")
API_URL = os.getenv("API_URL", "http://api:8000")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data/tcc/transferencias/decisao")
KC_URL = os.getenv("KC_URL", "http://keycloak:8080")
KC_REALM = os.getenv("KC_REALM", "tcc")
KC_JWKS_URL = os.getenv("KC_JWKS_URL", f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/certs")
KC_ISSUER = os.getenv("KC_ISSUER", "http://localhost:8080/realms/tcc")
KC_CLIENT_ID = os.getenv("KC_CLIENT_ID", "operador-cli")
KC_ADMIN_USER = os.getenv("KC_ADMIN_USER", "admin")
KC_ADMIN_PASSWORD = os.getenv("KC_ADMIN_PASSWORD", "admin")
ARQUIVO_EVENTOS = os.getenv("ARQUIVO_EVENTOS", "/data/eventos.csv")
ARQUIVO_DISPOSITIVOS = os.getenv("ARQUIVO_DISPOSITIVOS", "/app/dispositivos.json")
ARQUIVO_LIMITES = os.getenv("ARQUIVO_LIMITES", "/app/limites.json")
HORA_SIMULADA = os.getenv("HORA_SIMULADA", "").strip()   # ex.: "03:00"; vazio = hora real
FUSO = ZoneInfo(os.getenv("FUSO", "America/Sao_Paulo"))

app = FastAPI(title="Gateway (PEP)")
_jwks = jwt.PyJWKClient(KC_JWKS_URL, cache_keys=True)
_api = httpx.Client(base_url=API_URL, timeout=10)
_http = httpx.Client(timeout=5)
_lock_csv = threading.Lock()
_lock_estado = threading.Lock()

CAMPOS = ["momento", "modo", "operador", "dispositivo", "hora", "valor", "destino",
          "decisao", "motivo", "latencia_ms"]


def _ler_json(caminho: str) -> dict:
    try:
        with open(caminho, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


DISPOSITIVOS = {k: v for k, v in _ler_json(ARQUIVO_DISPOSITIVOS).items() if not k.startswith("_")}
LIMITES = _ler_json(ARQUIVO_LIMITES).get("limites", {})
JANELA_SEGUNDOS = float(LIMITES.get("janela_segundos", 600))
NEGACOES_PARA_BLOQUEIO = int(LIMITES.get("negacoes_para_bloqueio", 3))

# Estado mantido pelo gateway (o OPA não guarda estado entre consultas)
_historico = defaultdict(deque)      # operador -> deque[(instante, valor)] de ordens aceitas
_negacoes_seguidas = defaultdict(int)
_bloqueados = {}                     # operador -> instante (epoch) do bloqueio


# ---------------------------------------------------------------------------
# Registro de eventos
# ---------------------------------------------------------------------------
def _preparar_arquivo_eventos():
    """Se o arquivo existir com colunas antigas, guarda-o com outro nome e começa um novo."""
    if not os.path.exists(ARQUIVO_EVENTOS):
        return
    with open(ARQUIVO_EVENTOS, encoding="utf-8") as f:
        cabecalho = f.readline().strip().split(",")
    if cabecalho != CAMPOS:
        antigo = ARQUIVO_EVENTOS.replace(".csv", f"_antigo_{datetime.now():%Y%m%d_%H%M%S}.csv")
        os.rename(ARQUIVO_EVENTOS, antigo)


_preparar_arquivo_eventos()


def registrar_evento(**evento):
    """Acrescenta uma linha ao log de eventos (cria o arquivo com cabeçalho se preciso)."""
    evento = {"momento": datetime.now(timezone.utc).isoformat(), "modo": MODO, **evento}
    with _lock_csv:
        novo = not os.path.exists(ARQUIVO_EVENTOS)
        with open(ARQUIVO_EVENTOS, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CAMPOS)
            if novo:
                w.writeheader()
            w.writerow({c: evento.get(c, "") for c in CAMPOS})


# ---------------------------------------------------------------------------
# Verificações
# ---------------------------------------------------------------------------
def hora_atual() -> str:
    """Horário usado nas regras: o simulado (definido pelo experimentador) ou o real."""
    return HORA_SIMULADA or datetime.now(FUSO).strftime("%H:%M")


def validar_token(request: Request) -> dict:
    """Valida o token de acesso (assinatura, emissor, validade e cliente). Lança ValueError se inválido."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise ValueError("token ausente")
    token = auth.split(" ", 1)[1]
    try:
        chave = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, chave, algorithms=["RS256"], issuer=KC_ISSUER,
                            options={"verify_aud": False})
    except jwt.PyJWTError as e:
        raise ValueError(f"token inválido: {e}")
    if claims.get("azp") != KC_CLIENT_ID:
        raise ValueError("token emitido para outro cliente")
    return claims


def dispositivo_da_conexao(request: Request) -> str:
    """Identificador (CN) do certificado de dispositivo verificado pelo Nginx, ou '' se não houver."""
    if request.headers.get("x-client-cert-verify", "") != "SUCCESS":
        return ""
    m = re.search(r"CN=([^,/]+)", request.headers.get("x-client-cert-dn", ""))
    return m.group(1).strip() if m else ""


def verificar_dispositivo(operador: str, dispositivo: str):
    """Controle 1: a credencial só vale na estação autorizada para aquele operador."""
    if not dispositivo:
        raise PermissionError("certificado de dispositivo ausente")
    autorizado = DISPOSITIVOS.get(operador)
    if autorizado is None:
        raise PermissionError("operador sem dispositivo cadastrado")
    if dispositivo != autorizado:
        raise PermissionError(f"dispositivo não autorizado para {operador}")


def resumo_janela(operador: str, agora: float) -> tuple[float, int]:
    """Remove ordens fora da janela e devolve (valor acumulado, quantidade) das restantes."""
    fila = _historico[operador]
    while fila and agora - fila[0][0] > JANELA_SEGUNDOS:
        fila.popleft()
    return sum(v for _, v in fila), len(fila)


def consultar_opa(entrada: dict) -> dict:
    """Controle 2: pede a decisão ao OPA. Se o OPA não responder, nega (falha segura)."""
    try:
        r = _http.post(OPA_URL, json={"input": entrada})
        r.raise_for_status()
        resultado = r.json().get("result")
        if not resultado:
            return {"permitir": False, "motivos": ["política não encontrada no OPA"]}
        return resultado
    except httpx.HTTPError:
        return {"permitir": False, "motivos": ["mecanismo de política indisponível"]}


# ---------------------------------------------------------------------------
# Integração com o Keycloak (papel de administrador de política - PA)
# ---------------------------------------------------------------------------
def _token_admin() -> str:
    r = _http.post(f"{KC_URL}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": KC_ADMIN_USER, "password": KC_ADMIN_PASSWORD,
    })
    r.raise_for_status()
    return r.json()["access_token"]


def _id_usuario(operador: str, cab: dict) -> str | None:
    r = _http.get(f"{KC_URL}/admin/realms/{KC_REALM}/users",
                  params={"username": operador, "exact": "true"}, headers=cab)
    r.raise_for_status()
    usuarios = r.json()
    return usuarios[0]["id"] if usuarios else None


def keycloak_definir_operador(operador: str, ativo: bool) -> str:
    """Ativa ou desativa a conta no Keycloak; ao desativar, encerra todas as sessões."""
    try:
        cab = {"Authorization": f"Bearer {_token_admin()}"}
        uid = _id_usuario(operador, cab)
        if uid is None:
            return "usuário não encontrado no Keycloak"
        _http.put(f"{KC_URL}/admin/realms/{KC_REALM}/users/{uid}",
                  json={"enabled": ativo}, headers=cab).raise_for_status()
        if not ativo:
            _http.post(f"{KC_URL}/admin/realms/{KC_REALM}/users/{uid}/logout",
                       headers=cab).raise_for_status()
        return "ok"
    except httpx.HTTPError as e:
        return f"falha ao acessar o Keycloak: {e.__class__.__name__}"


def bloquear_operador(operador: str):
    """Interrompe o fluxo de transações: invalida os tokens já emitidos e desativa a conta."""
    _bloqueados[operador] = time.time()
    resultado = keycloak_definir_operador(operador, ativo=False)
    registrar_evento(operador=operador, decisao="bloqueio",
                     motivo=f"operador bloqueado após {NEGACOES_PARA_BLOQUEIO} negações seguidas "
                            f"(Keycloak: {resultado})")


def negar(status: int, motivo: str, inicio: float, **evento):
    registrar_evento(decisao="negado", motivo=motivo,
                     latencia_ms=round((time.perf_counter() - inicio) * 1000, 2), **evento)
    return JSONResponse(status_code=status, content={"decisao": "negado", "motivo": motivo})


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------
@app.get("/saude")
def saude():
    return {"status": "ok", "modo": MODO, "hora_simulada": HORA_SIMULADA or None}


@app.get("/saldo")
def saldo(request: Request):
    try:
        validar_token(request)
    except ValueError as e:
        return JSONResponse(status_code=401, content={"decisao": "negado", "motivo": str(e)})
    return _api.get("/saldo").json()


@app.post("/transferencias")
async def transferencias(request: Request):
    inicio = time.perf_counter()
    corpo = await request.json()
    dispositivo = dispositivo_da_conexao(request)
    hora = hora_atual()
    evento = {"valor": corpo.get("valor", ""), "destino": corpo.get("destino", ""),
              "dispositivo": dispositivo, "hora": hora}

    # 1. Autenticação: em qualquer modo, o token precisa ser válido
    try:
        claims = validar_token(request)
    except ValueError as e:
        return negar(401, str(e), inicio, operador="", **evento)
    operador = claims.get("preferred_username", "desconhecido")

    if MODO == "zero_trust":
        # Operador bloqueado: tokens emitidos antes do bloqueio deixam de valer
        if operador in _bloqueados and claims.get("iat", 0) <= _bloqueados[operador]:
            return negar(401, "sessão revogada: operador bloqueado", inicio, operador=operador, **evento)

        # Controle 1: vinculação da credencial ao dispositivo
        try:
            verificar_dispositivo(operador, dispositivo)
        except PermissionError as e:
            return negar(403, str(e), inicio, operador=operador, **evento)

        # Controle 2: autorização contextual (OPA)
        try:
            valor = float(corpo.get("valor", 0))
        except (TypeError, ValueError):
            valor = 0.0
        with _lock_estado:
            acumulado, quantidade = resumo_janela(operador, time.time())
        decisao = consultar_opa({"valor": valor, "valor_acumulado_janela": acumulado,
                                 "quantidade_janela": quantidade, "hora": hora})
        if not decisao.get("permitir", False):
            motivo = "; ".join(sorted(decisao.get("motivos", [])))
            with _lock_estado:
                _negacoes_seguidas[operador] += 1
                bloquear = _negacoes_seguidas[operador] >= NEGACOES_PARA_BLOQUEIO
            resposta = negar(403, motivo, inicio, operador=operador, **evento)
            if bloquear:
                bloquear_operador(operador)
            return resposta

    # 3. Encaminha a ordem à API
    resposta = _api.post("/transferencias", json=corpo, headers={"X-Operador": operador})
    latencia = round((time.perf_counter() - inicio) * 1000, 2)
    if resposta.status_code == 201:
        with _lock_estado:
            _historico[operador].append((time.time(), float(corpo.get("valor", 0))))
            _negacoes_seguidas[operador] = 0
        registrar_evento(operador=operador, decisao="permitido", motivo="",
                         latencia_ms=latencia, **evento)
    else:
        registrar_evento(operador=operador, decisao="erro_api",
                         motivo=resposta.json().get("detail", ""), latencia_ms=latencia, **evento)
    return JSONResponse(status_code=resposta.status_code, content=resposta.json())


@app.post("/reset")
def reset():
    """Prepara uma nova execução do experimento: saldo, histórico e bloqueios zerados.

    Reativa no Keycloak todos os operadores do inventário (e não só os bloqueados
    nesta execução do gateway), pois a conta pode ter sido desativada antes de o
    gateway ser reiniciado.
    """
    with _lock_estado:
        _historico.clear()
        _negacoes_seguidas.clear()
        _bloqueados.clear()
    reativados = {op: keycloak_definir_operador(op, ativo=True) for op in DISPOSITIVOS}
    return {"api": _api.post("/reset").json(), "operadores_reativados": reativados}
