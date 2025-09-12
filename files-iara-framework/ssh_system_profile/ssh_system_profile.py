#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH Inventory Collector
- Reutiliza a lógica de conexão do seu ssh_connectivity_probe.py (OpenSSH via subprocess).
- Conecta em hosts do inventário e coleta:
  * Distro/versão, kernel
  * Pacotes instalados (nome + versão)
  * Serviços (habilitados/estado) e serviços em execução
  * Processos (pid, ppid, user, comm, args)
  * Versões de runtimes/servers comuns (python, node, java, nginx, apache, mysql, postgres, mongo, redis, docker, etc.)
- Saídas:
  * CSV resumo por host
  * Pasta out/DETAILS contendo um JSON detalhado por host
Opcional: XLSX com xlsxwriter.

Compatível Python 3.6+.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ===== Util =====

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

def run_local(cmd, timeout):
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, timeout=timeout
    )

# ===== Inventário (mesma heurística do seu probe) =====

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

# ===== TCP pré-cheque (idêntico em espírito) =====

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

# ===== SSH base (equivalente ao seu script) =====

def ssh_base_cmd(user, host, port, identity, timeout, strict, legacy):
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
    cmd += ["{}@{}".format(user, host)]
    return cmd

def ssh_exec(user, host, port, identity, timeout, strict, legacy, remote_cmd, overall_timeout):
    # Executa "bash -lc" para suportar PATHs antigos
    base = ssh_base_cmd(user, host, port, identity, timeout, strict, legacy)
    cmd = base + ["bash", "-lc", remote_cmd]
    p = run_local(cmd, overall_timeout)
    return p.returncode, p.stdout, p.stderr

# ===== Coleta Remota =====

# Deteção de comandos
def has_cmd(user, host, port, identity, timeout, strict, legacy, cmd, overall_timeout):
    rc, _, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, "command -v {} >/dev/null 2>&1; echo $?".format(cmd), overall_timeout)
    # rc aqui é do ssh, então verifique pelo echo $? na saída
    if rc != 0:
        return False
    rc2, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, "command -v {} >/dev/null 2>&1; echo $?".format(cmd), overall_timeout)
    return out.strip().endswith("0")

def read_os_release(user, host, port, identity, timeout, strict, legacy, overall_timeout):
    rc, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, "cat /etc/os-release 2>/dev/null || true", overall_timeout)
    info = {"id": "", "version_id": "", "name": "", "pretty_name": ""}
    for line in out.splitlines():
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            key = k.lower()
            if key == "id": info["id"] = v
            elif key == "version_id": info["version_id"] = v
            elif key == "name": info["name"] = v
            elif key == "pretty_name": info["pretty_name"] = v
    return info

def read_kernel(user, host, port, identity, timeout, strict, legacy, overall_timeout):
    rc, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, "uname -sr || true", overall_timeout)
    return out.strip()

def list_packages(user, host, port, identity, timeout, strict, legacy, overall_timeout, os_id):
    # Retorna lista de dicts: [{"name":..., "version":...}, ...]
    # Tenta por prioridade: dpkg, rpm, apk, pacman
    cmds = []
    if os_id in ("debian", "ubuntu", "raspbian", "linuxmint"):
        cmds = [("dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null", "dpkg")]
    elif os_id in ("rhel", "centos", "rocky", "almalinux", "ol", "fedora", "sles", "opensuse", "suse"):
        cmds = [("rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null", "rpm")]
    else:
        cmds = [
            ("dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null", "dpkg"),
            ("rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null", "rpm"),
            ("apk info -vv 2>/dev/null", "apk"),
            ("pacman -Q 2>/dev/null", "pacman"),
        ]
    for cmd, tool in cmds:
        rc, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, cmd, overall_timeout)
        if out.strip():
            pkgs = []
            if tool in ("dpkg", "rpm", "pacman"):
                for line in out.splitlines():
                    parts = line.strip().split("\t") if "\t" in line else line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        ver = parts[1].strip()
                        pkgs.append({"name": name, "version": ver})
            elif tool == "apk":
                # linhas tipo: "bash-5.2.15-r0 description..." → pegar "bash-5.2.15-r0"
                for line in out.splitlines():
                    token = line.split()[0].strip()
                    # separar nome-versão (heurística simples)
                    m = re.match(r"^(.+)-([0-9].+)$", token)
                    if m:
                        pkgs.append({"name": m.group(1), "version": m.group(2)})
                    else:
                        pkgs.append({"name": token, "version": ""})
            return pkgs
    return []

def list_services_systemd(user, host, port, identity, timeout, strict, legacy, overall_timeout):
    # unit files (enabled/disabled), e unidades ativas
    rc1, out1, _ = ssh_exec(
        user, host, port, identity, timeout, strict, legacy,
        "systemctl list-unit-files --type=service --no-pager --no-legend --all 2>/dev/null || true",
        overall_timeout
    )
    unit_files = []
    for line in out1.splitlines():
        # formato: name.service     enabled
        parts = [p for p in line.split() if p]
        if len(parts) >= 2 and parts[0].endswith(".service"):
            unit_files.append({"unit": parts[0], "enabled": parts[-1]})
    rc2, out2, _ = ssh_exec(
        user, host, port, identity, timeout, strict, legacy,
        "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null || true",
        overall_timeout
    )
    running = []
    for line in out2.splitlines():
        # formato típico: name.service loaded active running ...
        parts = [p for p in line.split() if p]
        if parts and parts[0].endswith(".service"):
            running.append(parts[0])
    return unit_files, running

def list_services_sysv_openrc(user, host, port, identity, timeout, strict, legacy, overall_timeout):
    # Tentativas diversas em sistemas antigos
    # service --status-all (Debian/Ubuntu SysV): linhas com [+] ou [-]
    rc, out, _ = ssh_exec(
        user, host, port, identity, timeout, strict, legacy,
        "(service --status-all 2>/dev/null || true)",
        overall_timeout
    )
    svc = []
    if out.strip():
        for line in out.splitlines():
            line = line.strip()
            # ex: [ + ]  ssh
            name = line.replace("[", " ").replace("]", " ").strip()
            name = re.sub(r"\s+", " ", name)
            # última palavra deve ser o nome
            parts = name.split()
            if parts:
                svc.append({"name": parts[-1], "raw": line})
    else:
        # OpenRC (rc-status)
        rc2, out2, _ = ssh_exec(
            user, host, port, identity, timeout, strict, legacy,
            "(rc-status 2>/dev/null || true)",
            overall_timeout
        )
        if out2.strip():
            for line in out2.splitlines():
                if "[" in line and "]" in line:
                    name = line.split("[", 1)[0].strip()
                    svc.append({"name": name, "raw": line})
    return svc

def list_processes(user, host, port, identity, timeout, strict, legacy, overall_timeout):
    rc, out, _ = ssh_exec(
        user, host, port, identity, timeout, strict, legacy,
        "ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null || true",
        overall_timeout
    )
    procs = []
    for line in out.splitlines():
        # pid ppid user comm args...
        parts = line.strip().split(None, 4)
        if len(parts) >= 5:
            pid, ppid, usr, comm, args = parts
            procs.append({"pid": pid, "ppid": ppid, "user": usr, "comm": comm, "args": args})
    return procs

VERSION_CMDS = [
    ("python3", "python3 --version 2>&1 | head -n1"),
    ("python",  "python --version 2>&1 | head -n1"),
    ("pip3",    "pip3 --version 2>&1 | head -n1"),
    ("node",    "node --version 2>&1 | head -n1"),
    ("npm",     "npm --version 2>&1 | head -n1"),
    ("java",    "java -version 2>&1 | head -n1"),
    ("nginx",   "nginx -v 2>&1 | head -n1"),
    ("apache2", "apache2 -v 2>&1 | head -n1"),
    ("httpd",   "httpd -v 2>&1 | head -n1"),
    ("mysql",   "mysql --version 2>&1 | head -n1"),
    ("psql",    "psql --version 2>&1 | head -n1"),
    ("mongod",  "mongod --version 2>&1 | head -n1"),
    ("redis-server", "redis-server --version 2>&1 | head -n1"),
    ("docker",  "docker --version 2>&1 | head -n1"),
    ("containerd", "containerd --version 2>&1 | head -n1"),
    ("kubectl", "kubectl version --client --short 2>&1 | head -n1"),
    ("go",      "go version 2>&1 | head -n1"),
    ("rustc",   "rustc --version 2>&1 | head -n1"),
    ("php",     "php -v 2>&1 | head -n1"),
    ("perl",    "perl -v 2>&1 | head -n1"),
    ("ruby",    "ruby -v 2>&1 | head -n1"),
]

def collect_versions(user, host, port, identity, timeout, strict, legacy, overall_timeout):
    versions = {}
    for name, cmd in VERSION_CMDS:
        rc, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, f"command -v {name} >/dev/null 2>&1 && {cmd} || true", overall_timeout)
        line = out.strip()
        if line:
            versions[name] = line
    # systemctl --version
    rc, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, "systemctl --version 2>&1 | head -n1 || true", overall_timeout)
    if out.strip():
        versions["systemctl"] = out.strip()
    # package manager versions
    for pm, vcmd in [
        ("dpkg", "dpkg-query --version 2>&1 | head -n1"),
        ("rpm", "rpm --version 2>&1 | head -n1"),
        ("apk", "apk --version 2>&1 | head -n1"),
        ("pacman", "pacman --version 2>&1 | head -n1"),
        ("yum", "yum --version 2>&1 | head -n1"),
        ("dnf", "dnf --version 2>&1 | head -n1"),
        ("zypper", "zypper --version 2>&1 | head -n1"),
    ]:
        rc, out, _ = ssh_exec(user, host, port, identity, timeout, strict, legacy, f"command -v {pm} >/dev/null 2>&1 && {vcmd} || true", overall_timeout)
        if out.strip():
            versions[pm] = out.strip()
    return versions

# ===== Coleta por host =====

def collect_host(entry, dflt, out_dir, per_cmd_timeout):
    hostname = (entry.get(dflt["host_f"]) or "").strip()
    ipaddr   = (entry.get(dflt["ip_f"]) or "").strip()
    target   = ipaddr if ipaddr and is_ipv4(ipaddr) else (hostname if hostname else "")
    res = {
        "hostname": hostname, "ip_address": ipaddr, "status": "failed",
        "distro": "", "kernel": "", "pkg_count": 0, "services_running_count": 0, "process_count": 0,
        "details_path": "", "collected_at": now_str(), "note": ""
    }
    if not target:
        res["note"] = "Registro sem hostname/ip"
        return res

    try:
        port = int((entry.get(dflt["port_f"]) or "").strip()) if dflt["port_f"] else dflt["port"]
    except Exception:
        port = dflt["port"]

    # pré-cheque TCP
    pre = tcp_probe(target, port, min(dflt["timeout"], 5))
    if pre != "ok":
        res["note"] = "TCP {}".format(pre)
        return res

    users = []
    if dflt["user_f"] and entry.get(dflt["user_f"]):
        users.append((entry.get(dflt["user_f"]) or "").strip())
    users += dflt["users"]
    seen = set()
    users = [u for u in users if u and not (u in seen or seen.add(u))]

    # tenta autenticar com a primeira conta que funcionar
    authed = None
    last_err = ""
    for user in users:
        try:
            rc, _, err = ssh_exec(user, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], "true", per_cmd_timeout)
            if rc == 0:
                authed = user
                break
            last_err = err
        except Exception as e:
            last_err = str(e)

    if not authed:
        res["note"] = "auth_failed/{}".format((last_err or "").strip().splitlines()[-1][:120])
        return res

    # Coletas
    osinfo = read_os_release(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout)
    kernel = read_kernel(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout)

    pkgs = list_packages(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout, (osinfo.get("id") or "").lower())
    # Serviços
    # Tenta systemd; se vazio, tenta sysv/openrc
    unit_files, running_units = list_services_systemd(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout)
    svc_fallback = []
    if not unit_files and not running_units:
        svc_fallback = list_services_sysv_openrc(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout)

    procs = list_processes(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout)
    versions = collect_versions(authed, target, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"], per_cmd_timeout)

    # Monta JSON detalhado
    details = {
        "host": {"hostname": hostname, "ip_address": ipaddr, "user": authed},
        "os": {"id": osinfo.get("id"), "version_id": osinfo.get("version_id"), "pretty_name": osinfo.get("pretty_name"), "kernel": kernel},
        "packages": pkgs,  # [{name, version}]
        "services": {
            "systemd": {"unit_files": unit_files, "running": running_units} if unit_files or running_units else None,
            "fallback": svc_fallback if svc_fallback else None
        },
        "processes": procs,
        "versions": versions,  # dict: nome_cmd -> linha de versão
        "collected_at": now_str()
    }

    # Salva JSON por host
    os.makedirs(os.path.join(out_dir, "DETAILS"), exist_ok=True)
    safe_name = (hostname or ipaddr or "host").replace("/", "_")
    json_path = os.path.join(out_dir, "DETAILS", "{}.json".format(safe_name))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(details, f, ensure_ascii=False, indent=2)

    # Resumo
    res.update({
        "status": "ok",
        "distro": details["os"]["pretty_name"] or (details["os"]["id"] or ""),
        "kernel": details["os"]["kernel"],
        "pkg_count": len(pkgs),
        "services_running_count": len(running_units) if running_units else (len(svc_fallback) if svc_fallback else 0),
        "process_count": len(procs),
        "details_path": os.path.relpath(json_path, out_dir),
        "note": ""
    })
    return res

# ===== Escritas =====

SUMMARY_COLS = [
    "hostname","ip_address","status","distro","kernel",
    "pkg_count","services_running_count","process_count",
    "details_path","collected_at","note"
]

def write_summary_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in SUMMARY_COLS})

def write_summary_xlsx(path, rows):
    try:
        import xlsxwriter
    except ImportError:
        print("Aviso: instale xlsxwriter para gerar XLSX.", file=sys.stderr)
        return
    wb = xlsxwriter.Workbook(path)
    ws = wb.add_worksheet("summary")
    head = wb.add_format({"bold": True, "bg_color": "#F2F2F2", "border": 1})
    for c, col in enumerate(SUMMARY_COLS):
        ws.write(0, c, col, head)
    for r, row in enumerate(rows, start=1):
        for c, col in enumerate(SUMMARY_COLS):
            ws.write(r, c, "" if row.get(col) is None else str(row.get(col)))
    wb.close()

# ===== Args / Main =====

def parse_args():
    p = argparse.ArgumentParser(description="Coleta inventário detalhado via SSH a partir de um inventário CSV/XLSX.")
    p.add_argument("--inventory", required=True, help="CSV/XLSX com hostname e/ou ip_address; opcionais: ssh_user, ssh_port")
    p.add_argument("--target-user", default="root", help="Usuário padrão")
    p.add_argument("--user-fallbacks", default="root,ec2-user,ubuntu,centos,opc,admin,azureuser,rocky,oracle", help="Fallbacks separados por vírgula")
    p.add_argument("--identity", help="Caminho da chave privada SSH")
    p.add_argument("--port", type=int, default=22, help="Porta padrão SSH")
    p.add_argument("--timeout", type=int, default=10, help="Timeout de conexão SSH (s)")
    p.add_argument("--cmd-timeout", type=int, default=20, help="Timeout por comando remoto (s)")
    p.add_argument("--workers", type=int, default=20, help="Concorrência")
    p.add_argument("--strict-known-hosts", action="store_true", help="Usar StrictHostKeyChecking=accept-new")
    p.add_argument("--legacy-crypto", action="store_true", help="Habilita algoritmos legados (+ssh-rsa,+dh-group14-sha1)")
    p.add_argument("--out-dir", default="ssh_inventory_out", help="Diretório de saída")
    p.add_argument("--out-xlsx", help="Escreve também XLSX resumo")
    p.add_argument("--sample", type=int, default=0, help="Processar apenas N primeiros hosts")
    return p.parse_args()

def main():
    a = parse_args()

    # Expandir chave
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

    out_dir = os.path.abspath(a.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    results = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(collect_host, r, dflt, out_dir, a.cmd_timeout) for r in rows]
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({
                    "hostname": "", "ip_address": "", "status": "failed",
                    "distro":"", "kernel":"", "pkg_count":0, "services_running_count":0, "process_count":0,
                    "details_path":"", "collected_at": now_str(), "note": "exception: {}".format(e)
                })

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(out_dir, "ssh_inventory_summary_{}.csv".format(ts))
    write_summary_csv(csv_path, results)
    print("Resumo CSV:", csv_path)
    if a.out_xlsx:
        write_summary_xlsx(a.out_xlsx, results)
        print("Resumo XLSX:", os.path.abspath(a.out_xlsx))

    # Estatísticas simples
    ok = sum(1 for r in results if r["status"] == "ok")
    fail = len(results) - ok
    print("Total hosts:", len(results), "| ok:", ok, "| failed:", fail)

if __name__ == "__main__":
    main()
