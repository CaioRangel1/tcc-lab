# Laboratório do TCC — Controles zero trust contra ameaças internas

Ambiente que simula a interface de transferências de um prestador de serviços
de tecnologia (PSTI) e avalia controles zero trust contra um ataque com
credencial válida, inspirado no incidente da C&M Software (2025).

## Componentes

| Serviço   | Papel                                          | NIST SP 800-207 |
|-----------|------------------------------------------------|-----------------|
| api       | API de transferências (conta reserva)          | Recurso         |
| keycloak  | Login dos operadores e tokens                  | PA / identidade |
| gateway   | Intercepta, verifica e decide o encaminhamento | PEP             |
| nginx     | TLS (perímetro) ou mTLS (zero trust)           | PEP             |
| opa       | Regras de contexto (passo 3)                   | PE              |

O modo é definido no arquivo `.env` (`MODO=perimetro` ou `MODO=zero_trust`).

## Pré-requisitos

- Docker Desktop
- Python 3.10+ (para os scripts de ataque): `pip install -r ataque/requirements.txt`

## Passo 1 — modo perímetro (linha de base)

```bash
docker compose up -d --build
python ataque/ataque.py
```

Resultado esperado: todas as ordens aceitas — a credencial válida basta.

## Passo 2 — controle 1: vinculação ao dispositivo (mTLS)

Cada estação de trabalho tem um certificado emitido pela CA do laboratório
(`certs/estacao-operador1.crt`, `certs/estacao-operador2.crt`). O arquivo
`gateway/dispositivos.json` é o inventário que diz qual estação pertence a
qual operador.

```bash
# 1. Gerar os certificados das estações
docker compose up -d --force-recreate certgen

# 2. Trocar MODO=perimetro por MODO=zero_trust no arquivo .env e aplicar
docker compose up -d --force-recreate gateway nginx

# 3. Cenários
python ataque/ataque.py --dispositivo nenhum             # criminoso no próprio computador
python ataque/ataque.py --dispositivo estacao-operador2  # agente interno na própria estação
python ataque/ataque.py --dispositivo estacao-operador1 --quantidade 20  # estação autorizada
```

Resultados esperados:
- `nenhum`: barrado pelo Nginx (sem certificado)
- `estacao-operador2`: barrado pelo gateway (estação não autorizada para operador1)
- `estacao-operador1`: aceito — este controle sozinho não impede o uso na estação certa

## Passo 3 — controle 2: autorização contextual (OPA)

A cada ordem, o gateway envia ao OPA o valor, o total e a quantidade de ordens
aceitas na janela de tempo e o horário. As regras ficam em `opa/politica.rego` e
os limites em `opa/data.json`. Após 3 negações seguidas, o operador é bloqueado:
os tokens já emitidos deixam de valer e a conta é desativada no Keycloak.

O horário usado pelas regras vem de `HORA_SIMULADA` no `.env` (vazio = hora real).

```bash
# Subir o OPA e reconstruir o gateway
docker compose up -d --build

# Cenário A - ataque de madrugada (HORA_SIMULADA=03:00 no .env)
python ataque/ataque.py --dispositivo estacao-operador1

# Trocar para HORA_SIMULADA=10:00 no .env e aplicar
docker compose up -d --force-recreate gateway

# Cenário B - ataque "discreto" em horário comercial, abaixo do limite por ordem
python ataque/ataque.py --dispositivo estacao-operador1 --valor 900000

# Cenário C - uso normal em horário comercial
python ataque/ataque.py --dispositivo estacao-operador1 --valor 50000 --quantidade 10
```

Testes das políticas (opcional, requer o OPA instalado): `opa test opa/ -v`

## Passo 4 — experimentos oficiais e análise

Roda todos os cenários (C1 a C5 e uso legítimo L1 e L2), várias vezes cada,
trocando sozinho o modo e o horário. No final, gera tabelas e gráficos.

```bash
pip install -r experimentos/requirements.txt
python experimentos/executar.py              # 5 repetições (padrão)
```

Saída em `resultados/experimento_<data>/`: `execucoes.csv`, `tabela_ataques.csv`,
`tabela_legitimo.csv`, `grafico_*.png`, `resumo.txt` e `metadados.json`.

## Arquivos de resultados (`resultados/`)

- `ataque_<dispositivo>_<data>.csv` — o que o atacante conseguiu, ordem a ordem
- `eventos.csv` — cada decisão do gateway (operador, dispositivo, motivo, latência)

Para derrubar o ambiente: `docker compose down`
