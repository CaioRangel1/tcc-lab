# Política de autorização contextual das ordens de transferência.
#
# O OPA atua como mecanismo de política (Policy Engine - NIST SP 800-207):
# recebe do gateway os atributos de cada ordem e decide se ela pode seguir.
# Os limites ficam em data.json, separados das regras.
#
# Entrada esperada (input), enviada pelo gateway:
#   valor                  valor da ordem atual (R$)
#   valor_acumulado_janela soma das ordens já aceitas na janela de tempo (R$)
#   quantidade_janela      número de ordens já aceitas na janela de tempo
#   hora                   horário da operação, no formato "HH:MM"

package tcc.transferencias

import rego.v1

limites := data.limites

# ---------------------------------------------------------------------------
# Regras: cada regra violada acrescenta um motivo de negação
# ---------------------------------------------------------------------------

# Regra 1 - valor por transação
motivos contains "valor da transação acima do limite" if {
	input.valor > limites.valor_maximo_transacao
}

# Regra 2 - valor acumulado na janela de tempo
motivos contains "valor acumulado na janela acima do limite" if {
	input.valor_acumulado_janela + input.valor > limites.valor_maximo_janela
}

# Regra 3 - velocidade (quantidade de ordens na janela de tempo)
motivos contains "quantidade de ordens na janela acima do limite" if {
	input.quantidade_janela + 1 > limites.quantidade_maxima_janela
}

# Regra 4 - horário de operação
motivos contains "fora do horário permitido" if {
	not dentro_do_horario
}

dentro_do_horario if {
	minutos(input.hora) >= minutos(limites.inicio_operacao)
	minutos(input.hora) < minutos(limites.fim_operacao)
}

# Converte "HH:MM" em minutos desde a meia-noite
minutos(hhmm) := (to_number(partes[0]) * 60) + to_number(partes[1]) if {
	partes := split(hhmm, ":")
}

# ---------------------------------------------------------------------------
# Decisão final
# ---------------------------------------------------------------------------
default permitir := false

permitir if count(motivos) == 0

decisao := {
	"permitir": permitir,
	"motivos": motivos,
}
