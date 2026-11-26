"""
Análise dos experimentos: gera as tabelas e os gráficos do capítulo de resultados.

Uso (normalmente chamado por executar.py ao final):
    python experimentos/analise.py resultados/experimento_<data>
"""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "figure.dpi": 100})


def reais(v: float) -> str:
    return f"R$ {v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def milhoes(v: float) -> str:
    return f"{v / 1e6:,.1f}".replace(",", "X").replace(".", ",").replace("X", ".")


def motivo_interrupcao(g: pd.DataFrame) -> str:
    negadas = g[g["aceita"] == 0]
    return negadas["motivo"].iloc[0] if len(negadas) else "não houve"


def tabela_ataques(df: pd.DataFrame) -> pd.DataFrame:
    at = df[df["tipo"] == "ataque"]
    por_exec = at.groupby(["cenario", "nome_cenario", "repeticao"]).apply(
        lambda g: pd.Series({
            "enviadas": len(g),
            "aceitas": int(g["aceita"].sum()),
            "valor_transferido": g["total_transferido"].max(),
            "tempo_s": g["tempo_s"].max(),
            "motivo_interrupcao": motivo_interrupcao(g),
        }), include_groups=False).reset_index()
    t = por_exec.groupby(["cenario", "nome_cenario"]).agg(
        execucoes=("repeticao", "count"),
        enviadas_media=("enviadas", "mean"),
        aceitas_media=("aceitas", "mean"),
        aceitas_dp=("aceitas", "std"),
        valor_medio=("valor_transferido", "mean"),
        valor_dp=("valor_transferido", "std"),
        tempo_medio_s=("tempo_s", "mean"),
        motivo_interrupcao=("motivo_interrupcao", lambda s: s.mode().iloc[0]),
    ).reset_index()
    return t.fillna(0)


def tabela_legitimo(df: pd.DataFrame) -> pd.DataFrame:
    lg = df[df["tipo"] == "legitimo"]
    t = lg.groupby(["cenario", "nome_cenario"]).agg(
        ordens=("ordem", "count"),
        aceitas=("aceita", "sum"),
        latencia_media_ms=("latencia_ms", "mean"),
        latencia_p95_ms=("latencia_ms", lambda s: s.quantile(0.95)),
    ).reset_index()
    t["falsos_positivos"] = t["ordens"] - t["aceitas"]
    t["taxa_falsos_positivos_%"] = 100 * t["falsos_positivos"] / t["ordens"]
    return t


def grafico_valor_acumulado(df: pd.DataFrame, pasta: str):
    at = df[(df["tipo"] == "ataque") & (df["repeticao"] == 1)]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for (cid, nome), g in at.groupby(["cenario", "nome_cenario"]):
        ax.plot(g["ordem"], g["total_transferido"] / 1e6, marker="o" if len(g) < 20 else None,
                markersize=3, label=f"{cid} – {nome}")
    ax.set_xlabel("Número da ordem de transferência")
    ax.set_ylabel("Valor acumulado transferido (R$ milhões)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(pasta, "grafico_valor_acumulado.png"), dpi=200)
    plt.close(fig)


def grafico_barras(t: pd.DataFrame, pasta: str):
    fig, ax = plt.subplots(figsize=(8, 4.5))
    barras = ax.bar(t["cenario"], t["valor_medio"] / 1e6, color="#4a6fa5")
    for b, v in zip(barras, t["valor_medio"]):
        ax.annotate(milhoes(v), (b.get_x() + b.get_width() / 2, b.get_height()),
                    ha="center", va="bottom", fontsize=9, xytext=(0, 2), textcoords="offset points")
    ax.set_xlabel("Cenário")
    ax.set_ylabel("Valor médio transferido (R$ milhões)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(pasta, "grafico_valor_por_cenario.png"), dpi=200)
    plt.close(fig)


def grafico_latencia(df: pd.DataFrame, pasta: str):
    lg = df[df["tipo"] == "legitimo"]
    grupos = [(f"{cid} – {nome}", g["latencia_ms"].values)
              for (cid, nome), g in lg.groupby(["cenario", "nome_cenario"])]
    if not grupos:
        return
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.boxplot([v for _, v in grupos], tick_labels=[n for n, _ in grupos], showfliers=False)
    ax.set_ylabel("Latência por ordem (ms)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(pasta, "grafico_latencia.png"), dpi=200)
    plt.close(fig)


def gerar(pasta: str):
    df = pd.read_csv(os.path.join(pasta, "execucoes.csv"))
    ta = tabela_ataques(df)
    tl = tabela_legitimo(df)
    ta.to_csv(os.path.join(pasta, "tabela_ataques.csv"), index=False, encoding="utf-8-sig")
    tl.to_csv(os.path.join(pasta, "tabela_legitimo.csv"), index=False, encoding="utf-8-sig")
    grafico_valor_acumulado(df, pasta)
    grafico_barras(ta, pasta)
    grafico_latencia(df, pasta)

    with open(os.path.join(pasta, "resumo.txt"), "w", encoding="utf-8") as f:
        f.write("RESULTADOS DOS ATAQUES (média por execução)\n")
        for _, r in ta.iterrows():
            f.write(f"{r['cenario']} | {r['nome_cenario']}: {r['aceitas_media']:.1f}/{r['enviadas_media']:.1f} "
                    f"ordens aceitas (dp {r['aceitas_dp']:.1f}), {reais(r['valor_medio'])} transferidos, "
                    f"interrupção: {r['motivo_interrupcao']}\n")
        f.write("\nUSO LEGÍTIMO\n")
        for _, r in tl.iterrows():
            f.write(f"{r['cenario']} | {r['nome_cenario']}: {int(r['aceitas'])}/{int(r['ordens'])} aceitas, "
                    f"falsos positivos {r['taxa_falsos_positivos_%']:.1f}%, latência média "
                    f"{r['latencia_media_ms']:.1f} ms (p95 {r['latencia_p95_ms']:.1f} ms)\n")
    print(open(os.path.join(pasta, "resumo.txt"), encoding="utf-8").read())
    print(f"Tabelas e gráficos salvos em: {pasta}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Uso: python experimentos/analise.py resultados/experimento_<data>")
    gerar(sys.argv[1])
