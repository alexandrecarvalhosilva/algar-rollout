#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Connectivity Probe (rodar na bastion) -> CSV/XLSX no formato especificado.
Compatível com Python 3.6+. Requer OpenSSH. Para XLSX: pip install xlsxwriter pandas openpyxl
"""

import argparse
import csv
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Layout exigido
OUT_COLS = [
    "hostname", "ip_address", "status", "response_time", "last_tested_at",
    "description", "pendencies", "failure_reason",
]

# Mensagens
FAIL_TXT = {
    "timeout": ("Timeout na conexão", "Verificar latência/ACL/VPN"),
    "auth_failed": ("Falha na autenticação", "Ajustar credenciais/chave SSH"),
    "network_unreachable": ("Rede inacessível", "Corrigir rota/DNS/VPN/firewall"),
    "connection_refused": ("Conexão recusada", "Confirmar serviço SSH e porta"),
    "key_rejected": ("Chave/algoritmo incompatível", "Aceitar/ajustar host key/KEX/cifra"),
    "unknown": ("Falha desconhecida", "Diagnóstico manual"),
}

# Fallback de usuários comuns
DEF_USERS = ["root", "ec2-user", "ubuntu", "centos", "opc", "admin", "azureuser", "rocky", "oracle"]

# Regex de classificação
PAT_CONN_REFUSED = re.compile(r"(kex_exchange_identification|banner exchange|connection (reset|closed) by|handshake failed)", re.I)
PAT_KEY_REJ      = re.compile(r"(no matching (host key type|key exchange method|cipher)|unable to negotiate|host key verification failed|remote host identification has changed)", re.I)
PAT_AUTH         = re.compile(r"(permission denied|too many authentication failures|no supported authentication methods|bad permissions|unprotected private key file|could not open.*identity|load key.*:|invalid format|authenticat)", re.I)
PAT_TIMEOUT      = re.compile(r"(timed out|i/o timeout)", re.I)
PAT_NETUNREACH   = re.compile(r"(no route to host|network is unreachable|could not resolve hostname|name or service not known|temporary failure in name resolution)", re.I)
PAT_PWEXP = re.compile(r"(password.*expired|password change required)", re.I)

# Util
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

def run(cmd, timeout):
    # Compatível com Python 3.6 (sem capture_output/text)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout
    )

# Inventário
def read_inventory(path):
    rows = []
    ext = os.path.splitext(path)[1].lower()
    if ext in [".xlsx", ".xls"]:
        try:
            import pandas as pd
        except ImportError:
            print("Instale: pip install pandas openpyxl", file=sys.stderr)
            sys.exit(2)
        df = pd.read_excel(path, dtype=str, engine="openpyxl").fillna("")
        df.columns = [c.strip().lower() for c in df.columns]
        rows = df.to_dict(orient="records")
    else:
        # CSV com tentativa de separadores comuns
        for sep in [",", ";", "|", "\t"]:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f, delimiter=sep)
                    tmp = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in reader]
                if tmp:
                    rows = tmp
                    break
            except Exception:
                rows = []
        if not rows:
            print("Falha ao ler inventário CSV.", file=sys.stderr)
            sys.exit(2)

    cols = set(rows[0].keys()) if rows else set()
    host_f = next((c for c in ["hostname", "host", "server", "nome", "name"] if c in cols), None) or "hostname"
    ip_f   = next((c for c in ["ip_address", "ip", "address", "endereco", "addr"] if c in cols), None) or "ip_address"
    user_f = next((c for c in ["ssh_user", "user", "usuario"] if c in cols), None)
    port_f = next((c for c in ["ssh_port", "port", "porta"] if c in cols), None)
    return rows, host_f, ip_f, user_f, port_f

# TCP pré-cheque
def tcp_probe(host, port, timeout):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return "ok"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        s = str(e).lower()
        if any(k in s for k in ["unreachable", "no route to host", "name or service not known", "temporary failure in name resolution"]):
            return "unreachable"
        return "unreachable"

# Classificação
def classify(stderr, fallback):
    s = stderr or ""
    if PAT_AUTH.search(s): return "auth_failed"
    if PAT_PWEXP.search(s): return "auth_failed"   # <— ADICIONE
    if PAT_KEY_REJ.search(s): return "key_rejected"
    if PAT_CONN_REFUSED.search(s): return "connection_refused"
    if PAT_NETUNREACH.search(s): return "network_unreachable"
    if PAT_TIMEOUT.search(s): return "timeout"
    return fallback or "unknown"

# Comando SSH
def ssh_cmd(host, user, port, identity, timeout, strict, legacy):
    cmd = [
        "ssh", "-F", "/dev/null",
        "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "StrictHostKeyChecking=" + ("accept-new" if strict else "no"),
        "-o", "ConnectTimeout={}".format(timeout),
    ]
    if legacy:
        cmd += [
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "-o", "KexAlgorithms=+diffie-hellman-group14-sha1",
        ]
    if identity:
        cmd += ["-i", identity]
    if port and str(port) != "22":
        cmd += ["-p", str(port)]
    cmd += ["{}@{}".format(user, host), "true"]  # comando neutro
    return cmd

# Linhas de saída
def row_connected(h, ip, rtt):
    return {
        "hostname": h, "ip_address": ip, "status": "connected",
        "response_time": rtt, "last_tested_at": now_str(),
        "description": "Conectividade OK via bastion", "pendencies": "", "failure_reason": "",
    }

def row_failed(h, ip, reason, extra=""):
    desc, pend = FAIL_TXT[reason]
    if extra:
        desc = "{} ({})".format(desc, extra)
    return {
        "hostname": h, "ip_address": ip, "status": "failed",
        "response_time": 0, "last_tested_at": now_str(),
        "description": desc, "pendencies": pend, "failure_reason": reason,
    }

# Prova por host
def probe_one(entry, dflt, dbg, unknown_bucket):
    hostname = (entry.get(dflt["host_f"]) or "").strip()
    ipaddr   = (entry.get(dflt["ip_f"]) or "").strip()
    target   = ipaddr if ipaddr and is_ipv4(ipaddr) else (hostname if hostname else "")
    if not target:
        return {
            "hostname": hostname, "ip_address": ipaddr, "status": "not_tested",
            "response_time": "", "last_tested_at": "",
            "description": "Registro sem hostname/ip", "pendencies": "Corrigir inventário", "failure_reason": "",
        }

    try:
        port = int((entry.get(dflt["port_f"]) or "").strip()) if dflt["port_f"] else dflt["port"]
    except Exception:
        port = dflt["port"]

    users = []
    if dflt["user_f"] and entry.get(dflt["user_f"]):
        users.append((entry.get(dflt["user_f"]) or "").strip())
    users += dflt["users"]
    seen = set()
    users = [u for u in users if u and not (u in seen or seen.add(u))]

    pre = tcp_probe(target, port, min(dflt["timeout"], 5))
    if pre == "timeout":     return row_failed(hostname, ipaddr, "timeout")
    if pre == "unreachable": return row_failed(hostname, ipaddr, "network_unreachable")
    if pre == "refused":     return row_failed(hostname, ipaddr, "connection_refused")

    last_err = ""
    for user in users:
        start = time.time()
        cmd = ssh_cmd(target, user, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"])
        try:
            p = run(cmd, dflt["timeout"] + 5)
            rtt = int((time.time() - start) * 1000)
            if p.returncode == 0:
                return row_connected(hostname, ipaddr, rtt)
            last_err = p.stderr or ""
            if dbg:
                dbg.write("{} user={} rc={} err={}\n".format(target, user, p.returncode, last_err.strip()))
            reason = classify(last_err, None)
            if reason != "auth_failed":
                return row_failed(hostname, ipaddr, reason)
            # auth_failed → tentar próximo user
        except subprocess.TimeoutExpired:
            return row_failed(hostname, ipaddr, "timeout")
        except Exception as e:
            last_err = str(e)
            if dbg:
                dbg.write("{} user={} EXC={}\n".format(target, user, last_err))
            reason = classify(last_err, None)
            if reason != "auth_failed":
                return row_failed(hostname, ipaddr, reason)

    # TCP ok, nenhum usuário autenticou → auth_failed
    if last_err and unknown_bucket is not None:
        key = (last_err.strip().splitlines()[-1])[:200]
        unknown_bucket.append(key)
    return row_failed(hostname, ipaddr, "auth_failed")

# Escrita CSV
def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in OUT_COLS})

# Escrita XLSX opcional
def write_xlsx(path, rows):
    try:
        import xlsxwriter
    except ImportError:
        print("Aviso: instale xlsxwriter para gerar XLSX.", file=sys.stderr)
        return
    wb = xlsxwriter.Workbook(path)
    ws = wb.add_worksheet("data")
    head = wb.add_format({"bold": True, "bg_color": "#F2F2F2", "border": 1})
    num = wb.add_format({"num_format": "0"})
    for c, col in enumerate(OUT_COLS):
        ws.write(0, c, col, head)
    for r, row in enumerate(rows, start=1):
        for c, col in enumerate(OUT_COLS):
            v = row.get(col, "")
            if col == "response_time" and isinstance(v, int):
                ws.write_number(r, c, v, num)
            else:
                ws.write(r, c, "" if v is None else str(v))
    ws2 = wb.add_worksheet("lists")
    statuses = ["connected", "failed", "pending", "not_tested"]
    fails = ["timeout", "auth_failed", "network_unreachable", "connection_refused", "key_rejected", "unknown"]
    ws2.write_row(0, 0, ["status_list"] + statuses)
    ws2.write_row(1, 0, ["failure_reason_list"] + fails)
    from xlsxwriter.utility import xl_rowcol_to_cell
    s0, s1 = xl_rowcol_to_cell(0, 1), xl_rowcol_to_cell(0, len(statuses))
    f0, f1 = xl_rowcol_to_cell(1, 1), xl_rowcol_to_cell(1, len(fails))
    wb.define_name("status_list", "=lists!{}:{}".format(s0, s1))
    wb.define_name("failure_reason_list", "=lists!{}:{}".format(f0, f1))
    maxr = len(rows) + 1000
    ws.data_validation(1, 2, maxr, 2, {"validate": "list", "source": "=status_list"})
    ws.data_validation(1, 7, maxr, 7, {"validate": "list", "source": "=failure_reason_list"})
    wb.close()

# Args
def parse_args():
    p = argparse.ArgumentParser(description="Teste SSH na bastion e gera CSV/XLSX no formato exigido.")
    p.add_argument("--inventory", required=True, help="CSV/XLSX com hostname e/ou ip_address; opcionais: ssh_user, ssh_port")
    p.add_argument("--target-user", default="root", help="Usuário padrão")
    p.add_argument("--user-fallbacks", default=",".join(DEF_USERS), help="Fallbacks separados por vírgula")
    p.add_argument("--identity", help="Caminho da chave privada SSH")
    p.add_argument("--port", type=int, default=22, help="Porta padrão")
    p.add_argument("--timeout", type=int, default=10, help="Timeout por host (s)")
    p.add_argument("--workers", type=int, default=50, help="Concorrência")
    p.add_argument("--strict-known-hosts", action="store_true", help="Usar StrictHostKeyChecking=accept-new")
    p.add_argument("--legacy-crypto", action="store_true", help="Habilita algoritmos legados (+ssh-rsa,+dh-group14-sha1)")
    p.add_argument("--out-csv", help="CSV de saída")
    p.add_argument("--out-xlsx", help="XLSX de saída (opcional)")
    p.add_argument("--debug-log", help="Arquivo de debug opcional")
    p.add_argument("--sample", type=int, default=0, help="Testar apenas N primeiros hosts")
    return p.parse_args()

# Main
def main():
    a = parse_args()

    # Expandir caminho da chave (corrige ~ e $VARS)
    if a.identity:
        a.identity = os.path.abspath(os.path.expanduser(os.path.expandvars(a.identity)))
        if not os.path.exists(a.identity):
            print("Erro: chave não encontrada: {}".format(a.identity), file=sys.stderr)
            sys.exit(2)

    rows, host_f, ip_f, user_f, port_f = read_inventory(a.inventory)
    if a.sample > 0:
        rows = rows[:a.sample]

    dflt = {
        "host_f": host_f, "ip_f": ip_f, "user_f": user_f, "port_f": port_f,
        "users": [u for u in [a.target_user] + [x.strip() for x in a.user_fallbacks.split(",")] if u],
        "identity": a.identity, "timeout": a.timeout, "port": a.port,
        "strict": a.strict_known_hosts, "legacy": a.legacy_crypto,
    }

    dbg = open(a.debug_log, "a") if a.debug_log else None
    unknown_msgs = []
    try:
        results = []
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            futs = [ex.submit(probe_one, r, dflt, dbg, unknown_msgs) for r in rows]
            for fut in as_completed(futs):
                results.append(fut.result())

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_csv = a.out_csv or os.path.join(os.path.dirname(os.path.abspath(a.inventory)), "ssh_connectivity_{}.csv".format(ts))
        write_csv(out_csv, results)
        if a.out_xlsx:
            write_xlsx(a.out_xlsx, results)

        # Resumo
        ok = sum(1 for r in results if r["status"] == "connected")
        fail = sum(1 for r in results if r["status"] == "failed")
        pend = sum(1 for r in results if r["status"] == "pending")
        nt   = sum(1 for r in results if r["status"] == "not_tested")
        print("Total: {} | connected: {} | failed: {} | pending: {} | not_tested: {}".format(len(results), ok, fail, pend, nt))
        print("CSV: {}".format(out_csv))
        if a.out_xlsx:
            print("XLSX: {}".format(a.out_xlsx))

        # Breakdown por failure_reason
        counts = {}
        for r in results:
            k = r.get("failure_reason", "")
            if k:
                counts[k] = counts.get(k, 0) + 1
        if counts:
            print("failure_reason:")
            for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
                print("  {}: {}".format(k, v))

        # Amostras de stderr desconhecido (se houver)
        if unknown_msgs:
            from collections import Counter
            top = Counter(unknown_msgs).most_common(5)
            print("amostras_unknown_stderr:")
            for msg, qty in top:
                print("  [{}] {}".format(qty, msg))

    finally:
        if dbg:
            dbg.close()

if __name__ == "__main__":
    main()
