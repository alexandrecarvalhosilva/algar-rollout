# Relatório de Alcance – Consolidação, Entregáveis e Cronograma

**Data:** 2025-09-09 08:10:00

## 1) Visão geral

Consolidamos os hosts **não alcançados por automação** na última varredura e classificamos os motivos técnicos. Também apontamos os **arquivos para envio ao cliente**, as **listas internas de planejamento** e um **cronograma com tempo estimado** para as próximas atividades.

---

## 2) Resumo quantitativo (base de não alcançados)

* **Total de hosts não alcançados:** **972**
* **Quebra por motivo:**

  * **Sem ICMP e SSH:** 902 (**92,7%**)
  * **ICMP bloqueado (somente SSH):** 68 (**7,0%**)
  * **SSH 22 fechado/filtrado (somente ICMP):** 2 (**0,2%**)

### Observações de logs (SSH)

* **KEX fechado pelo host:** 150
* **Timeout durante banner SSH:** 4

> Fonte: `hosts_nao_alcancados_enriquecido_final.csv` e `motivos_ansible.csv` (consolidados nesta entrega).

---

## 3) Entregáveis para o cliente (validação de acesso)

Envio recomendado ao time de **Rede/Security/Cliente**:

* **/mnt/data/hosts\_validacao\_cliente.csv** — 972 linhas (colunas: `host,motivo,detalhe`).
* **/mnt/data/resumo\_motivos.csv** — contagem por `motivo` e `detalhe` para priorização de chamados.

**Pedidos objetivos ao cliente** (por linha da lista):

* Validar **rota/ACL/firewall** orquestrador ↔ host.
* Quando `motivo = SSH 22 fechado/filtrado`: liberar **22/TCP** (ou informar bastion/jump host).
* Quando `motivo = ICMP bloqueado (somente SSH)`: confirmar que política de ICMP é intencional.
* Quando `motivo = Sem ICMP e SSH`: confirmar **status do host** (ativo/desligado) e correção de rota/DNS.

---

## 4) Listas internas (planejamento e execução)

* **Acessíveis (ICMP+SSH):** usar `lista_full_ok.txt` (gerado no seu workspace) para planejar validações adicionais. *Contagem esperada:* **919** hosts.
* **Listas auxiliares (já geradas):** `lista_ssh_ok.txt`, `lista_ssh_fail.txt`, `lista_icmp_ok.txt`, `lista_icmp_fail.txt`, `lista_icmp_only.txt`, `lista_ssh_only.txt`.
* **Consolidados desta entrega:**

  * **/mnt/data/hosts\_nao\_alcancados\_enriquecido\_final.csv** — 972 linhas, com `host,motivo,detalhe`.

> Caso precise regenerar as listas a partir de `alcance_scan.csv`, utilize `scripts/resumo-alcance.sh alcance_scan.csv`.

---

## 5) Próximas validações nos hosts acessíveis

Aplicar nos **919** hosts com ICMP+SSH OK:

* **Acesso/Segurança:** padronizar chaves, `MaxStartups`, banner legal, `AllowUsers/Groups`.
* **Privilégios:** usuário do Ansible com `sudo` sem senha para coleta.
* **Ambiente:** presença de `python3`, NTP/timezone, espaço em disco/`inodes`, swap, SELinux/firewalld.
* **Inventário:** SO (`/etc/redhat-release`/`/etc/issue`), hostname/FQDN, IPs/domínios de busca.

---

## 6) Cronograma com estimativas (MD)

> Estimativas baseadas em prática de campo com **Ansible** e **Linux** em ambientes \~1.9k hosts. Podem variar conforme SLA de Rede/Security e janelas do cliente.

| Fase        | Atividade                           | Escopo                                                      |               Esforço estimado\* | Duração (calendário) | Responsável   | Dependências         | Critério de pronto                               |
| ----------- | ----------------------------------- | ----------------------------------------------------------- | -------------------------------: | -------------------: | ------------- | -------------------- | ------------------------------------------------ |
| **D0**      | Publicar relatório & abrir chamados | Enviar `hosts_validacao_cliente.csv` + `resumo_motivos.csv` |                       **0,5 pd** |        **Mesmo dia** | Operações     | –                    | Chamados abertos e protocolo de envio registrado |
| **D0–D+1**  | Triage de amostras                  | Amostra de 20–30 hosts por motivo                           |                       **0,5 pd** |       **1 dia útil** | Operações     | D0                   | Retornos coletados e ajustes nos chamados        |
| **D+1–D+2** | Correções de Rede/Security          | 902 “Sem ICMP e SSH”, 68 “Somente SSH”, 2 “Somente ICMP”    |      **1–2 pd** para coordenação |     **2 dias úteis** | Rede/Security | D0                   | Regras/rotas ajustadas em 1ª onda                |
| **D+2**     | **Revarrer #1** (KPIs)              | Varredura completa e comparação                             |                       **0,5 pd** |        **Mesmo dia** | Operações     | Correções iniciais   | Indicadores atualizados e deltas reportados      |
| **D+3–D+4** | Ajustes SSH/KEX/banner              | Tratar hosts com erro de handshake                          |                         **1 pd** |     **2 dias úteis** | Sistemas      | Revarrer #1          | Queda >70% nos erros de KEX/banner               |
| **D+4–D+5** | Padronização de acesso              | Usuário Ansible/sudo, chaves                                |                         **1 pd** |     **2 dias úteis** | Sistemas      | Revarrer #1          | Checklist aplicado em >90% dos acessíveis        |
| **D+5**     | **Revarrer #2** (KPIs)              | Nova medição pós-ajustes                                    |                       **0,5 pd** |        **Mesmo dia** | Operações     | Fases anteriores     | KPIs com melhoria sustentada                     |
| **D+5–D+7** | Plano Python 3 (onde necessário)    | Instalação controlada c/ *playbook*                         | **1–2 pd** coordenação + janelas |     **2 dias úteis** | Sistemas/App  | Validação de impacto | `python3 --version` OK e Ansible funcional       |
| **D+7**     | **Revarrer #3** & fechamento        | Consolidação final e backlog residual                       |                       **0,5 pd** |        **Mesmo dia** | Operações     | Todas                | Relatório final e próximos passos aprovados      |

\* **pd = pessoa-dia.** Os esforços acima consideram paralelização típica (execuções Ansible em *forks* e atendimento de Rede/Security em lote).

---

## 7) Observações e riscos

* **Inventário desatualizado** pode inflar “Sem ICMP e SSH”. Tratar divergências de DNS/IP.
* **Dependência de terceiros/Security** pode alongar prazos de liberação.
* **Ambientes legados**: predominância de Python 2.7 → planejar migração gradual para Python 3.x.

---

## 8) Referências rápidas

* Para revalidações: `ansible -i inventory/hosts.ini <grupo> -m ping -o -f 20 --timeout 5`
* Checagem rápida de SO nos acessíveis: `ansible <grupo_full_ok> -m raw -a 'cat /etc/redhat-release || cat /etc/issue'`
* Geração das listas: `scripts/resumo-alcance.sh alcance_scan.csv`

> Dúvidas ou ajustes: podemos expandir o cronograma por ondas (por BU/site) ou anexar dashboards com evolução dos KPIs por rodada de varredura.
