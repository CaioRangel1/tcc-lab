# Testes automatizados da política (executar com: opa test opa/ -v)
package tcc.transferencias_test

import rego.v1

import data.tcc.transferencias

base := {"valor": 50000, "valor_acumulado_janela": 0, "quantidade_janela": 0, "hora": "10:00"}

test_ordem_normal_permitida if {
	transferencias.decisao.permitir with input as base
}

test_valor_acima_do_limite if {
	d := transferencias.decisao with input as object.union(base, {"valor": 3000000})
	not d.permitir
	"valor da transação acima do limite" in d.motivos
}

test_acumulado_acima_do_limite if {
	d := transferencias.decisao with input as object.union(base, {"valor": 900000, "valor_acumulado_janela": 4500000})
	not d.permitir
	"valor acumulado na janela acima do limite" in d.motivos
}

test_velocidade_acima_do_limite if {
	d := transferencias.decisao with input as object.union(base, {"quantidade_janela": 20})
	not d.permitir
	"quantidade de ordens na janela acima do limite" in d.motivos
}

test_madrugada_negada if {
	d := transferencias.decisao with input as object.union(base, {"hora": "03:00"})
	not d.permitir
	"fora do horário permitido" in d.motivos
}

test_limite_do_horario if {
	transferencias.decisao.permitir with input as object.union(base, {"hora": "06:30"})
	not transferencias.decisao.permitir with input as object.union(base, {"hora": "18:30"})
}

test_ataque_do_caso_real_viola_varias_regras if {
	d := transferencias.decisao with input as {"valor": 3000000, "valor_acumulado_janela": 6000000, "quantidade_janela": 2, "hora": "02:03"}
	count(d.motivos) == 3
}
