# Especificação — `ssh_connectivity_probe.py`

## Objetivo

Testar acesso **SSH direto a partir da bastion** a uma lista de máquinas e gerar um **relatório de conectividade** no formato exigido (CSV e opcional XLSX).

---

## Requisitos

* **Runtime:** Python ≥ 3.6.
* **Dependências externas:** OpenSSH client (`ssh` no PATH).
* **Dependências Python opcionais:**

  * `pandas` + `openpyxl` para ler `.xlsx` (entrada).
  * `xlsxwriter` para escrever `.xlsx` (saída).
* **Permissões de chave:** arquivo `--identity` com permissão adequada (ex.: `chmod 600`).

---

## Entrada

### 1) Inventário (`--inventory`)

* **Formato:** CSV **ou** Excel (`.xlsx`/`.xls`).
* **Encoding esperado:** UTF-8.
* **Detecção de separador (CSV):** tenta `,` `;` `|` `\t`.
* **Normalização de colunas:** nomes das colunas são convertidos para **lowercase** e `strip()`.

#### Colunas reconhecidas

| Papel            | Nomes aceitos                                             | Obrigatório                                     | Observações                                                                          |
| ---------------- | --------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------ |
| Hostname         | `hostname` \| `host` \| `server` \| `nome` \| `name`      | Pelo menos **um** entre hostname ou ip\_address | Se ambos presentes, o target padrão é o **IP** válido; caso contrário, usa hostname. |
| IP               | `ip_address` \| `ip` \| `address` \| `endereco` \| `addr` | Pelo menos **um** entre hostname ou ip\_address | Validação IPv4 simples (`ipaddress`).                                                |
| Usuário por host | `ssh_user` \| `user` \| `usuario`                         | Não                                             | Se existir, tem precedência sobre `--target-user`.                                   |
| Porta por host   | `ssh_port` \| `port` \| `porta`                           | Não                                             | Se existir, tem precedência sobre `--port`.                                          |

> Regra: **hostname ou ip\_address** deve existir no registro. Se nenhum, o registro sai como `not_tested`.

### 2) Parâmetros CLI

```bash
python3 ssh_connectivity_probe.py \
  --inventory <arquivo.csv|.xlsx> \
  [--target-user root] \
  [--user-fallbacks "root,ubuntu,ec2-user,..."] \
  [--identity /caminho/chave] \
  [--port 22] \
  [--timeout 10] \
  [--workers 50] \
  [--strict-known-hosts] \
  [--legacy-crypto] \
  [--out-csv <saida.csv>] \
  [--out-xlsx <saida.xlsx>] \
  [--debug-log <arquivo.log>] \
  [--sample N]
```

* `--identity`: expandido com `~` e `$VARS`; erro fatal se arquivo não existe.
* `--user-fallbacks`: lista em ordem de tentativa; default inclui: `root,ec2-user,ubuntu,centos,opc,admin,azureuser,rocky,oracle`.
* `--strict-known-hosts`: usa `StrictHostKeyChecking=accept-new` (sem, usa `no`).
* `--legacy-crypto`: adiciona **algoritmos legados** para equipamentos antigos:

  * `HostKeyAlgorithms=+ssh-rsa`
  * `PubkeyAcceptedKeyTypes=+ssh-rsa`
  * `KexAlgorithms=+diffie-hellman-group14-sha1`
* `--workers`: número de hosts em paralelo.
* `--sample N`: processa apenas os **N** primeiros registros (debug).

---

## Processamento

Para cada linha do inventário:

1. **Seleção do alvo (target):**

   * Se `ip_address` for IPv4 válido → usa IP.
   * Senão, usa `hostname`.
   * Se nenhum disponível → saída `not_tested`.

2. **Determinação de porta e usuários:**

   * Porta: `ssh_port` da linha ou `--port` (default 22).
   * Lista de usuários: `ssh_user` da linha (se existir) **+** `--user-fallbacks` (sem duplicar).

3. **Pré-checagem TCP (rápida):**

   * `socket.create_connection(target, port, timeout≤5)`.
   * Resultado:

     * `ok` → segue para SSH.
     * `timeout` → `failed` com `failure_reason=timeout`.
     * `refused` → `failed` com `failure_reason=connection_refused`.
     * `unreachable` → `failed` com `failure_reason=network_unreachable`.

4. **Tentativas de SSH:**

   * Para cada usuário da lista, chama `ssh` com:

     * `-F /dev/null`
     * `-o IdentitiesOnly=yes`
     * `-o PreferredAuthentications=publickey`
     * `-o PasswordAuthentication=no`
     * `-o GSSAPIAuthentication=no`
     * `-o UserKnownHostsFile=/dev/null`
     * `-o GlobalKnownHostsFile=/dev/null`
     * `-o LogLevel=ERROR`
     * `-o StrictHostKeyChecking=no` **ou** `accept-new` (se `--strict-known-hosts`)
     * `-o ConnectTimeout=<timeout>`
     * `-i <identity>` (se fornecida)
     * `-p <port>` (se diferente de 22)
     * Comando remoto: `true`
   * Sucesso (`rc=0`) → `connected` e mede `response_time` em **ms**.
   * Falha → classifica pelo `stderr`. Se **auth\_failed**, tenta próximo usuário; se outro motivo, para e classifica.

5. **Classificação de falhas (`failure_reason`):**

   * `timeout` → mensagem contém `timed out` ou `I/O timeout`.
   * `network_unreachable` → `no route to host`, `network is unreachable`, `could not resolve hostname`, etc.
   * `connection_refused` → `kex_exchange_identification`, `banner exchange`, `connection reset/closed by`, `handshake failed`.
   * `key_rejected` → `no matching {host key type|kex|cipher}`, `unable to negotiate`, `host key verification failed`, `remote host identification has changed`.
   * `auth_failed` → `permission denied`, `too many authentication failures`, `no supported authentication methods`, problemas de chave (`bad permissions`, `unprotected private key file`, `could not open identity`, `invalid format`).
   * **Regra final:** se TCP ok e esgotou usuários sem autenticar → `auth_failed`.

6. **Concorrência:**

   * Usa `ThreadPoolExecutor(max_workers=--workers)`.

---

## Saída

### 1) Resumo no `stdout`

```
Total: <N> | connected: <n1> | failed: <n2> | pending: <n3> | not_tested: <n4>
CSV: <caminho/do/arquivo.csv>
[XLSX: <caminho/do/arquivo.xlsx>]
[failure_reason:
  <reason>: <count>
  ...]
[amostras_unknown_stderr:
  [qtd] <linha-de-stderr>
  ...]
```

> `pending` não é gerado automaticamente pelo programa; permanece 0.

### 2) Arquivo CSV obrigatório (`--out-csv` ou padrão)

* Se **não** informado: gera `ssh_connectivity_<YYYYMMDD_HHMMSS>.csv` no diretório do inventário.
* **Schema e regras:**

| Coluna           | Tipo      | Obrigatório | Regras e formato                                                                                                                                               |
| ---------------- | --------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hostname`       | Texto     | Sim\*       | Preencher se disponível. Pode ficar vazio se só houver IP.                                                                                                     |
| `ip_address`     | Texto     | Sim\*       | IPv4 válido se disponível. Pode ficar vazio se só houver hostname.                                                                                             |
| `status`         | Texto     | **Sim**     | Valores: `connected` \| `failed` \| `not_tested`.                                                                                                              |
| `response_time`  | Número    | Não         | Inteiro em **ms**. Preenchido apenas se `connected`.                                                                                                           |
| `last_tested_at` | Data/Hora | Não         | `YYYY-MM-DD HH:MM:SS`.                                                                                                                                         |
| `description`    | Texto     | Não         | Curta descrição da situação.                                                                                                                                   |
| `pendencies`     | Texto     | Não         | Ação sugerida.                                                                                                                                                 |
| `failure_reason` | Texto     | Não         | Preenchido **apenas** se `status=failed`. Valores possíveis: `timeout`, `auth_failed`, `network_unreachable`, `connection_refused`, `key_rejected`, `unknown`. |

> Regra: **hostname OU ip\_address** deve estar preenchido. `status` é obrigatório. Campos sem valor ficam vazios.

**Exemplo de linha `connected`:**

```csv
srv-web-01,192.168.1.100,connected,120,2025-09-10 14:30:00,Conectividade OK via bastion,,
```

**Exemplo de linha `failed`:**

```csv
srv-db-02,192.168.1.101,failed,0,2025-09-10 14:25:00,Falha na autenticação,Ajustar credenciais/chave SSH,auth_failed
```

### 3) Arquivo XLSX opcional (`--out-xlsx`)

* Aba `data` com o mesmo schema do CSV.
* Aba `lists` com listas válidas:

  * `status_list`: `connected, failed, pending, not_tested`
  * `failure_reason_list`: `timeout, auth_failed, network_unreachable, connection_refused, key_rejected, unknown`
* Validação de dados nas colunas `status` e `failure_reason`.

### 4) Log de debug opcional (`--debug-log`)

* Texto append. Exemplos de linhas:

```
10.0.10.102 user=root rc=255 err=Permission denied (publickey).
10.0.10.103 user=ubuntu rc=255 err=kex_exchange_identification: banner exchange: Connection closed
10.0.10.104 user=root EXC=Command '['ssh', ...]' timed out after 15 seconds
```

---

## Códigos de retorno (processo)

* `0`: execução normal, CSV gerado.
* `2`: erro de entrada (inventário ilegível, chave não encontrada).
* Outros erros não fatalmente capturados podem resultar em códigos do Python.

---

## Limitações

* Teste é **direto a partir da bastion** (sem `ProxyJump` múltiplo dentro do script).
* Somente **IPv4** validado. Hostname é resolvido pelo SSH.
* Não altera `known_hosts` (usa `UserKnownHostsFile=/dev/null`), salvo se `--strict-known-hosts`.

---

## Exemplos de execução

### Amostra de 10 hosts com log

```bash
python3 ssh_connectivity_probe.py \
  --inventory ./servidores.csv \
  --target-user root \
  --identity /root/.ssh/id_rsa \
  --timeout 12 \
  --workers 30 \
  --sample 10 \
  --debug-log ./ssh_debug.log \
  --out-csv /tmp/ssh_connectivity_sample.csv
```

### Execução completa com XLSX

```bash
python3 ssh_connectivity_probe.py \
  --inventory ./servidores.csv \
  --target-user root \
  --identity /root/.ssh/id_rsa \
  --timeout 12 \
  --workers 30 \
  --debug-log ./ssh_debug.log \
  --out-csv ./ssh_connectivity.csv \
  --out-xlsx ./ssh_connectivity.xlsx
```

### Equipamentos legados (KEX/hostkey antigos)

```bash
python3 ssh_connectivity_probe.py \
  --inventory ./servidores.csv \
  --target-user root \
  --identity /root/.ssh/id_rsa \
  --legacy-crypto \
  --out-csv ./ssh_connectivity.csv
```

---

## Fluxo resumido (pseudocódigo)

```
rows = ler_inventario()
for row in rows (em paralelo):
  target = ip if ipv4(ip) else hostname
  if !target: emit not_tested
  pre = tcp_probe(target, port, ≤5s)
  if pre != ok: classify pre → failed
  for user in [ssh_user_da_linha] + fallbacks:
    rc,stderr,lat = ssh(user@target, true)
    if rc == 0: emit connected(lat)
    if classify(stderr) != auth_failed: emit failed(classify); break
  if ninguém autenticou: emit failed(auth_failed)
escrever CSV (+XLSX se pedido)
imprimir resumo e breakdown
```

Pronto.
