Especificação pronta e template gerado.

# Formato de Importação SSH

**Arquivo:** CSV ou Excel (.xlsx)
**Encoding:** UTF-8
**Separador:** vírgula (,)

## Colunas obrigatórias

| Campo       | Tipo  | Descrição                    | Valores válidos                         | Exemplo       |
| ----------- | ----- | ---------------------------- | --------------------------------------- | ------------- |
| hostname    | Texto | Nome do servidor             | Deve existir na tabela `servers`        | srv-web-01    |
| ip\_address | Texto | IP do servidor (alternativo) | IPv4 válido                             | 192.168.1.100 |
| status      | Texto | Status da conectividade SSH  | connected, failed, pending, not\_tested | connected     |

> Regra: **hostname ou ip\_address** deve estar preenchido. **status** é obrigatório.

## Colunas opcionais

| Campo            | Tipo   | Descrição                  | Formato/Valores                                                                          | Exemplo                      |
| ---------------- | ------ | -------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------- |
| response\_time   | Número | Tempo de resposta em ms    | Inteiro ≥ 0                                                                              | 150                          |
| last\_tested\_at | Data   | Última verificação         | `YYYY-MM-DD HH:MM:SS`                                                                    | 2024-09-10 14:30:00          |
| description      | Texto  | Descrição da conectividade | Texto livre                                                                              | Conectividade OK via bastion |
| pendencies       | Texto  | Pendências a resolver      | Texto livre                                                                              | Configurar chave SSH         |
| failure\_reason  | Texto  | Motivo se `status=failed`  | timeout, auth\_failed, network\_unreachable, connection\_refused, key\_rejected, unknown | auth\_failed                 |

## Exemplo CSV

```csv
hostname,ip_address,status,response_time,last_tested_at,description,pendencies,failure_reason
srv-web-01,192.168.1.100,connected,120,2024-09-10 14:30:00,Conectividade OK via bastion,,
srv-db-02,192.168.1.101,failed,0,2024-09-10 14:25:00,Falha na autenticação,Configurar chave SSH correta,auth_failed
srv-app-03,192.168.1.102,pending,,,"Aguardando liberação de firewall",Abrir porta 22 no firewall,
srv-test-04,192.168.1.103,not_tested,,,Servidor novo ainda não testado,Fazer primeiro teste SSH,
```

## Regras

* Identificação: **preencher hostname ou ip\_address**. Pelo menos um.
* Status: **obrigatório**.
* Campos vazios: deixar em branco.
* Data: usar **ISO** `YYYY-MM-DD HH:MM:SS`.
* Texto com vírgula: **entre aspas duplas**.
* `failure_reason` só é avaliado quando `status=failed`.
