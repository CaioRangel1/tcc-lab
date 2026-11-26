"""
API de transferências (recurso protegido).

Simula a interface de um prestador de serviços de tecnologia que recebe ordens
de transferência das instituições clientes e as debita de uma conta reserva.
Não faz nenhuma verificação de segurança: confia em quem a chama, exatamente
como um sistema interno atrás de um perímetro. Só é acessível pelo gateway.
"""
import os
import threading
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

SALDO_INICIAL = float(os.getenv("SALDO_INICIAL", "1000000000"))

app = FastAPI(title="API de Transferências (fictícia)")

_lock = threading.Lock()
_estado = {"saldo": SALDO_INICIAL, "transferencias": []}


class OrdemTransferencia(BaseModel):
    valor: float = Field(gt=0, description="Valor em reais")
    destino: str = Field(min_length=1, description="Conta de destino")


@app.get("/saude")
def saude():
    return {"status": "ok"}


@app.get("/saldo")
def saldo():
    with _lock:
        return {
            "saldo": _estado["saldo"],
            "debitado": SALDO_INICIAL - _estado["saldo"],
            "quantidade_transferencias": len(_estado["transferencias"]),
        }


@app.post("/transferencias", status_code=201)
def transferir(ordem: OrdemTransferencia, x_operador: str = Header(default="desconhecido")):
    with _lock:
        if ordem.valor > _estado["saldo"]:
            raise HTTPException(status_code=422, detail="Saldo insuficiente na conta reserva")
        _estado["saldo"] -= ordem.valor
        registro = {
            "id": str(uuid.uuid4()),
            "operador": x_operador,
            "valor": ordem.valor,
            "destino": ordem.destino,
            "momento": datetime.now(timezone.utc).isoformat(),
        }
        _estado["transferencias"].append(registro)
        return {**registro, "saldo_restante": _estado["saldo"]}


@app.post("/reset")
def reset():
    """Restaura o saldo inicial entre execuções do experimento."""
    with _lock:
        _estado["saldo"] = SALDO_INICIAL
        _estado["transferencias"] = []
    return {"status": "saldo restaurado", "saldo": SALDO_INICIAL}
