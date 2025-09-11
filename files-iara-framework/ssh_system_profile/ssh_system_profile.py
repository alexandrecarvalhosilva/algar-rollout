#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Coleta de perfil de sistemas via SSH (rodar na bastion).
Entrada: inventário CSV/XLSX. Opcional: CSV do probe para filtrar conectados.
Saída: CSV (e XLSX opcional) com SO, distro, kernel, serviços, pacotes, Python, Zabbix, Qualys.
Requer: OpenSSH. Para XLSX: pip install xlsxwriter pandas openpyxl
"""

import argparse, csv, ipaddress, os, re, socket, subprocess, sys, time, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

OUT_COLS = [
    "hostname","ip_address","status","error","collected_at",
    "os_family","distro_id","distro_pretty_name","distro_version_id",
    "kernel","init_system",
    "services_running_count","services_sample",
    "pkg_manager","pkg_count","pkg_sample",
    "python_installed","python_version",
    "zabbix_agent_installed","zabbix_agent_version",
    "qualys_agent_installed","qualys_agent_version",
]

DEF_USERS = ["root","ec2-user","ubuntu","centos","opc","admin","azureuser","rocky","oracle"]

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s); return True
    except: return False

def run(cmd, timeout, input_data=None):
    return subprocess.run(
        cmd,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout
    )

def read_inventory(path):
    rows = []
    ext = os.path.splitext(path)[1].lower()
    if ext in [".xlsx", ".xls"]:
        try:
            import pandas as pd
        except ImportError:
            print("Instale: pip install pandas openpyxl", file=sys.stderr); sys.exit(2)
        df = pd.read_excel(path, dtype=str, engine="openpyxl").fillna("")
        df.columns = [c.strip().lower() for c in df.columns]
        rows = df.to_dict(orient="records")
    else:
        for sep in [",",";","|","\t"]:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f, delimiter=sep)
                    tmp = [{(k or "").strip().lower(): (v or "").strip() for k,v in r.items()} for r in reader]
                if tmp: rows = tmp; break
            except Exception:
                rows = []
        if not rows:
            print("Falha ao ler inventário CSV.", file=sys.stderr); sys.exit(2)

    cols = set(rows[0].keys()) if rows else set()
    host_f = next((c for c in ["hostname","host","server","nome","name"] if c in cols), None) or "hostname"
    ip_f   = next((c for c in ["ip_address","ip","address","endereco","addr"] if c in cols), None) or "ip_address"
    user_f = next((c for c in ["ssh_user","user","usuario"] if c in cols), None)
    port_f = next((c for c in ["ssh_port","port","porta"] if c in cols), None)
    return rows, host_f, ip_f, user_f, port_f

def read_connected_filter(path):
    ok = set()
    if not path: return ok
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            st = (r.get("status") or r.get("Status") or "").strip().lower()
            if st == "connected":
                ip = (r.get("ip_address") or r.get("ip") or "").strip()
                hn = (r.get("hostname") or r.get("host") or "").strip().lower()
                if ip: ok.add(("ip", ip))
                if hn: ok.add(("hn", hn))
    return ok

def ssh_cmd(host, user, port, identity, timeout, strict, legacy):
    cmd = [
        "ssh","-F","/dev/null",
        "-o","IdentitiesOnly=yes",
        "-o","PreferredAuthentications=publickey",
        "-o","PasswordAuthentication=no",
        "-o","GSSAPIAuthentication=no",
        "-o","UserKnownHostsFile=/dev/null",
        "-o","GlobalKnownHostsFile=/dev/null",
        "-o","LogLevel=ERROR",
        "-o","StrictHostKeyChecking=" + ("accept-new" if strict else "no"),
        "-o",f"ConnectTimeout={timeout}",
    ]
    if legacy:
        cmd += [
            "-o","HostKeyAlgorithms=+ssh-rsa",
            "-o","PubkeyAcceptedKeyTypes=+ssh-rsa",
            "-o","KexAlgorithms=+diffie-hellman-group14-sha1",
        ]
    if identity: cmd += ["-i", identity]
    if port and str(port)!="22": cmd += ["-p", str(port)]
    cmd += [f"{user}@{host}","bash","-s"]
    return cmd

REMOTE_SCRIPT = r'''set -euo pipefail
export LC_ALL=C
out_kv(){ printf "%s=%s\n" "$1" "$2"; }

# Base: SO e kernel
OS_ID=""; OS_NAME=""; OS_VER=""; OS_PRETTY=""
if [ -r /etc/os-release ]; then . /etc/os-release; OS_ID="${ID:-}"; OS_NAME="${NAME:-}"; OS_VER="${VERSION_ID:-}"; OS_PRETTY="${PRETTY_NAME:-}"
elif [ -r /usr/lib/os-release ]; then . /usr/lib/os-release; OS_ID="${ID:-}"; OS_NAME="${NAME:-}"; OS_VER="${VERSION_ID:-}"; OS_PRETTY="${PRETTY_NAME:-}"
fi
KERNEL="$(uname -r 2>/dev/null || echo)" || true

# Init
if command -v systemctl >/dev/null 2>&1; then INIT="systemd"
elif command -v rc-status >/dev/null 2>&1; then INIT="openrc"
else INIT="$(ps -p 1 -o comm= 2>/dev/null || echo)"; fi

# Serviços
SERV_CNT=0; SERV_SMP=""
if [ "${INIT}" = "systemd" ]; then
  mapfile -t S < <(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -n 50)
  SERV_CNT="$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | wc -l | awk '{print $1}')"
  SERV_SMP="$(printf "%s;" "${S[@]}" 2>/dev/null || true)"
elif command -v rc-status >/dev/null 2>&1; then
  mapfile -t S < <(rc-status -a 2>/dev/null | grep -E "started|running" | awk '{print $1}' | head -n 50)
  SERV_CNT="$(rc-status -a 2>/dev/null | grep -E "started|running" | wc -l | awk '{print $1}')"
  SERV_SMP="$(printf "%s;" "${S[@]}" 2>/dev/null || true)"
else
  # Debian-like fallback
  mapfile -t S < <(service --status-all 2>/dev/null | grep -E "^\s*\[\s*\+\s*\]" | awk '{print $4}' | head -n 50)
  SERV_CNT="$(service --status-all 2>/dev/null | grep -E "^\s*\[\s*\+\s*\]" | wc -l | awk '{print $1}')"
  SERV_SMP="$(printf "%s;" "${S[@]}" 2>/dev/null || true)"
fi

# Pacotes
PKG_MGR=""; PKG_CNT=0; PKG_SMP=""
if command -v dpkg-query >/dev/null 2>&1; then
  PKG_MGR="dpkg"
  PKG_CNT="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | wc -l | awk '{print $1}')"
  PKG_SMP="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort | head -n 30 | tr '\n' ';')"
elif command -v rpm >/dev/null 2>&1; then
  PKG_MGR="rpm"
  PKG_CNT="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | wc -l | awk '{print $1}')"
  PKG_SMP="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort | head -n 30 | tr '\n' ';')"
elif command -v apk >/dev/null 2>&1; then
  PKG_MGR="apk"
  PKG_CNT="$(apk info 2>/dev/null | wc -l | awk '{print $1}')"
  PKG_SMP="$(apk info 2>/dev/null | sort | head -n 30 | tr '\n' ';')"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
  PKG_CNT="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | wc -l | awk '{print $1}')"
  PKG_SMP="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort | head -n 30 | tr '\n' ';')"
fi

# Python
PY_INST="no"; PY_VER=""
if command -v python3 >/dev/null 2>&1; then PY_INST="yes"; PY_VER="$(python3 -V 2>&1 | awk '{print $2}')"
elif command -v python >/dev/null 2>&1; then PY_INST="yes"; PY_VER="$(python -V 2>&1 | awk '{print $2}')"
fi

# Zabbix
ZB_INST="no"; ZB_VER=""
if command -v zabbix_agentd >/dev/null 2>&1; then
  ZB_INST="yes"; ZB_VER="$(zabbix_agentd -V 2>&1 | head -n1 | awk '{print $NF}')"
elif command -v zabbix_agent2 >/dev/null 2>&1; then
  ZB_INST="yes"; ZB_VER="$(zabbix_agent2 -V 2>&1 | head -n1 | awk '{print $NF}')"
elif systemctl list-unit-files 2>/dev/null | grep -q '^zabbix-agent'; then ZB_INST="yes"
elif pgrep -fa zabbix_agent >/dev/null 2>&1; then ZB_INST="yes"
fi

# Qualys
QL_INST="no"; QL_VER=""
if systemctl list-unit-files 2>/dev/null | grep -q '^qualys-cloud-agent'; then QL_INST="yes"; fi
if pgrep -fa qualys >/dev/null 2>&1 || pgrep -fa qagent >/dev/null 2>&1; then QL_INST="yes"; fi
if [ -x /usr/local/qualys/cloud-agent/bin/qagent ]; then
  V="$(/usr/local/qualys/cloud-agent/bin/qagent -v 2>&1 || true)"; QL_VER="$(echo "$V" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
fi
if [ -z "$QL_VER" ] && [ -r /etc/qualys/cloud-agent/qualys-cloud-agent.conf ]; then
  QL_VER="$(grep -E '^AGENT_VERSION=' /etc/qualys/cloud-agent/qualys-cloud-agent.conf 2>/dev/null | cut -d= -f2)"
fi

# Saída em KV
out_kv os_family "linux"
out_kv distro_id "${OS_ID}"
out_kv distro_pretty_name "${OS_PRETTY}"
out_kv distro_version_id "${OS_VER}"
out_kv kernel "${KERNEL}"
out_kv init_system "${INIT}"
out_kv services_running_count "${SERV_CNT}"
out_kv services_sample "${SERV_SMP}"
out_kv pkg_manager "${PKG_MGR}"
out_kv pkg_count "${PKG_CNT}"
out_kv pkg_sample "${PKG_SMP}"
out_kv python_installed "${PY_INST}"
out_kv python_version "${PY_VER}"
out_kv zabbix_agent_installed "${ZB_INST}"
out_kv zabbix_agent_version "${ZB_VER}"
out_kv qualys_agent_installed "${QL_INST}"
out_kv qualys_agent_version "${QL_VER}"
'''

def parse_kv(text):
    res = {}
    for line in text.splitlines():
        if not line.strip(): continue
        if "=" not in line: continue
        k,v = line.split("=",1)
        res[k.strip()] = v.strip().strip()
    return res

def tcp_probe(host, port, timeout):
    try:
        with socket.create_connection((host, int(port)), timeout=min(timeout,5)):
            return "ok"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "unreachable"

def row_base(h, ip):
    return {
        "hostname": h, "ip_address": ip, "status":"failed", "error":"", "collected_at": now_str(),
        "os_family":"", "distro_id":"", "distro_pretty_name":"", "distro_version_id":"",
        "kernel":"", "init_system":"",
        "services_running_count":"", "services_sample":"",
        "pkg_manager":"", "pkg_count":"", "pkg_sample":"",
        "python_installed":"", "python_version":"",
        "zabbix_agent_installed":"", "zabbix_agent_version":"",
        "qualys_agent_installed":"", "qualys_agent_version":"",
    }

def collect_one(entry, dflt, filter_ok, dbg):
    hostname = (entry.get(dflt["host_f"]) or "").strip()
    ipaddr   = (entry.get(dflt["ip_f"]) or "").strip()
    target   = ipaddr if ipaddr and is_ipv4(ipaddr) else (hostname if hostname else "")
    row = row_base(hostname, ipaddr)

    # filtro "conectados" se fornecido
    if filter_ok:
        allow = False
        if ipaddr and ("ip", ipaddr) in filter_ok: allow = True
        if hostname and ("hn", hostname.lower()) in filter_ok: allow = True
        if not allow:
            row["status"] = "not_tested"; row["error"] = "filtered_by_connectivity_csv"; return row

    if not target:
        row["status"] = "not_tested"; row["error"] = "missing_hostname_or_ip"; return row

    try:
        port = int((entry.get(dflt["port_f"]) or "").strip()) if dflt["port_f"] else dflt["port"]
    except Exception:
        port = dflt["port"]

    users = []
    if dflt["user_f"] and entry.get(dflt["user_f"]):
        users.append((entry.get(dflt["user_f"]) or "").strip())
    users += dflt["users"]
    seen=set(); users=[u for u in users if u and not (u in seen or seen.add(u))]

    # checagem TCP rápida
    pre = tcp_probe(target, port, dflt["timeout"])
    if pre != "ok":
        row["status"]="failed"; row["error"]=f"tcp_{pre}"; return row

    last_err = ""
    for user in users:
        cmd = ssh_cmd(target, user, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"])
        try:
            p = run(cmd, dflt["timeout"] + 20, input_data=REMOTE_SCRIPT)
            if p.returncode == 0:
                kv = parse_kv(p.stdout)
                row.update({
                    "status":"ok", "error":"",
                    "os_family": kv.get("os_family",""),
                    "distro_id": kv.get("distro_id",""),
                    "distro_pretty_name": kv.get("distro_pretty_name",""),
                    "distro_version_id": kv.get("distro_version_id",""),
                    "kernel": kv.get("kernel",""),
                    "init_system": kv.get("init_system",""),
                    "services_running_count": kv.get("services_running_count",""),
                    "services_sample": kv.get("services_sample","").rstrip(";"),
                    "pkg_manager": kv.get("pkg_manager",""),
                    "pkg_count": kv.get("pkg_count",""),
                    "pkg_sample": kv.get("pkg_sample","").rstrip(";"),
                    "python_installed": kv.get("python_installed",""),
                    "python_version": kv.get("python_version",""),
                    "zabbix_agent_installed": kv.get("zabbix_agent_installed",""),
                    "zabbix_agent_version": kv.get("zabbix_agent_version",""),
                    "qualys_agent_installed": kv.get("qualys_agent_installed",""),
                    "qualys_agent_version": kv.get("qualys_agent_version",""),
                })
                return row
            else:
                last_err = (p.stderr or "").strip()
                if dbg: dbg.write(f"{target} user={user} rc={p.returncode} err={last_err}\n")
                # tentar próximo usuário somente se erro de auth
                if re.search(r"permission denied|no supported authentication methods|too many authentication failures", last_err, re.I):
                    continue
                # outros erros → falha
                row["status"]="failed"; row["error"]=f"ssh_error:{last_err[:180]}"; return row
        except subprocess.TimeoutExpired:
            row["status"]="failed"; row["error"]="ssh_timeout"; return row
        except Exception as e:
            last_err = str(e)
            if dbg: dbg.write(f"{target} user={user} EXC={last_err}\n")
            # segue próximo user se parecer auth
            if re.search(r"permission denied|authentication", last_err, re.I):
                continue
            row["status"]="failed"; row["error"]=f"ssh_exc:{last_err[:180]}"; return row

    row["status"]="failed"; row["error"]="auth_failed"; return row

def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLS); w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k,"") for k in OUT_COLS})

def write_xlsx(path, rows):
    try:
        import xlsxwriter
    except ImportError:
        print("Aviso: instale xlsxwriter para gerar XLSX.", file=sys.stderr); return
    wb = xlsxwriter.Workbook(path)
    ws = wb.add_worksheet("data")
    head = wb.add_format({"bold": True, "bg_color": "#F2F2F2", "border": 1})
    for c,col in enumerate(OUT_COLS): ws.write(0,c,col,head)
    for r,row in enumerate(rows, start=1):
        for c,col in enumerate(OUT_COLS):
            v = row.get(col,"")
            ws.write(r,c,v if v is not None else "")
    wb.close()

def parse_args():
    p = argparse.ArgumentParser(description="Perfil de sistemas via SSH (bastion) -> CSV/XLSX.")
    p.add_argument("--inventory", required=True, help="CSV/XLSX com hostname/ip; opcionais: ssh_user, ssh_port")
    p.add_argument("--connectivity-csv", help="CSV do ssh_connectivity_probe para filtrar status=connected")
    p.add_argument("--target-user", default="root", help="Usuário padrão")
    p.add_argument("--user-fallbacks", default=",".join(DEF_USERS), help="Fallbacks separados por vírgula")
    p.add_argument("--identity", help="Caminho da chave privada SSH")
    p.add_argument("--port", type=int, default=22, help="Porta padrão")
    p.add_argument("--timeout", type=int, default=12, help="Timeout por host (s)")
    p.add_argument("--workers", type=int, default=40, help="Concorrência")
    p.add_argument("--strict-known-hosts", action="store_true", help="StrictHostKeyChecking=accept-new")
    p.add_argument("--legacy-crypto", action="store_true", help="Habilita algoritmos legados (+ssh-rsa,+dh-group14-sha1)")
    p.add_argument("--out-csv", help="CSV de saída")
    p.add_argument("--out-xlsx", help="XLSX de saída (opcional)")
    p.add_argument("--debug-log", help="Arquivo de debug opcional")
    p.add_argument("--sample", type=int, default=0, help="Processar apenas N primeiros hosts")
    return p.parse_args()

def main():
    a = parse_args()
    if a.identity:
        a.identity = os.path.abspath(os.path.expanduser(os.path.expandvars(a.identity)))
        if not os.path.exists(a.identity):
            print(f"Erro: chave não encontrada: {a.identity}", file=sys.stderr); sys.exit(2)

    rows, host_f, ip_f, user_f, port_f = read_inventory(a.inventory)
    if a.sample>0: rows = rows[:a.sample]
    filt = read_connected_filter(a.connectivity_csv) if a.connectivity_csv else set()

    dflt = {
        "host_f": host_f, "ip_f": ip_f, "user_f": user_f, "port_f": port_f,
        "users": [u for u in [a.target_user] + [x.strip() for x in a.user_fallbacks.split(",")] if u],
        "identity": a.identity, "timeout": a.timeout, "port": a.port,
        "strict": a.strict_known_hosts, "legacy": a.legacy_crypto,
    }

    dbg = open(a.debug_log, "a") if a.debug_log else None
    try:
        results=[]
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            futs = [ex.submit(collect_one, r, dflt, filt, dbg) for r in rows]
            for f in as_completed(futs): results.append(f.result())

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_csv = a.out_csv or os.path.join(os.path.dirname(os.path.abspath(a.inventory)), f"system_profile_{ts}.csv")
        write_csv(out_csv, results)
        if a.out_xlsx: write_xlsx(a.out_xlsx, results)

        ok = sum(1 for r in results if r["status"]=="ok")
        fail = sum(1 for r in results if r["status"]=="failed")
        nt = sum(1 for r in results if r["status"]=="not_tested")
        print(f"Total: {len(results)} | ok: {ok} | failed: {fail} | not_tested: {nt}")
        print(f"CSV: {out_csv}")
        if a.out_xlsx: print(f"XLSX: {a.out_xlsx}")
    finally:
        if dbg: dbg.close()

if __name__ == "__main__":
    main()
