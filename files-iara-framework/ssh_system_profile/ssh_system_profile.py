#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ssh_system_profile.py — coleta via SSH (bastion)
Saída: único CSV com:
  - OS, kernel, init
  - TODOS os serviços UP (services_all)
  - TODOS os pacotes + versão (pkg_all)
  - Python: instalado + versão
  - Zabbix/Qualys: instalado + versão
  - Java: instalado + versão + JAVA_HOME
  - PHP: instalado + versão
  - Apache HTTPD: instalado + versão + flavor (httpd/apache2)
  - JBoss/WildFly: instalado + produto + versão + home + serviços/pids
  - WebSphere: instalado + versão + home
Compatível: Python 3.6+, OpenSSH. XLSX opcional: pandas/openpyxl/xlsxwriter
"""

import argparse, csv, ipaddress, os, re, socket, subprocess, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

OUT_COLS = [
    "hostname","ip_address","status","error","collected_at",
    "os_family","distro_id","distro_pretty_name","distro_version_id","kernel","init_system",
    "services_running_count","services_all",
    "pkg_manager","pkg_count","pkg_all",
    "python_installed","python_version",
    "zabbix_agent_installed","zabbix_agent_version",
    "qualys_agent_installed","qualys_agent_version",
    # Java
    "java_installed","java_version","java_home",
    # PHP
    "php_installed","php_version",
    # Apache
    "apache_installed","apache_version","apache_flavor","apache_service",
    # JBoss / WildFly
    "jboss_installed","jboss_product","jboss_version","jboss_home","jboss_services","jboss_pids",
    # WebSphere
    "websphere_installed","websphere_version","websphere_home",
]

DEF_USERS = ["root","ec2-user","ubuntu","centos","opc","admin","azureuser","rocky","oracle"]

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_ipv4(s):
    try: ipaddress.IPv4Address(s); return True
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
            except Exception: rows = []
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
    cmd += [f"{user}@{host}","sh","-c","bash --noprofile --norc -s || sh -s"]
    return cmd

REMOTE_SCRIPT = r'''set -u
export LC_ALL=C TERM=dumb
# PATH amplo p/ serviços/bins comuns
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:/usr/local/bin:/usr/local/sbin:/opt/IBM/WebSphere/AppServer/bin:/opt/jboss/bin:/opt/wildfly/bin:$PATH"

out_kv(){ printf "%s=%s\n" "$1" "$2"; }
trimsemi(){ X="$1"; X="${X%%;}" ; printf "%s" "$X"; }
joinsemi(){ tr '\n' ';' | sed 's/;*$//' || true; }

# ---------- SO ----------
OS_ID=""; OS_VER=""; OS_PRETTY=""
if [ -r /etc/os-release ]; then . /etc/os-release || true
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; OS_PRETTY="${PRETTY_NAME:-}"
elif [ -r /usr/lib/os-release ]; then . /usr/lib/os-release || true
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; OS_PRETTY="${PRETTY_NAME:-}"
fi
KERNEL="$(uname -r 2>/dev/null || echo)"

# ---------- INIT ----------
if command -v systemctl >/dev/null 2>&1; then INIT="systemd"
elif command -v rc-status >/dev/null 2>&1; then INIT="openrc"
else INIT="$(ps -p 1 -o comm= 2>/dev/null || echo)"; fi

# ---------- SERVIÇOS UP (completo) ----------
SERV_ALL=""
if [ "${INIT}" = "systemd" ]; then
  SERV_ALL="$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort -u | joinsemi)"
elif command -v rc-status >/dev/null 2>&1; then
  SERV_ALL="$(rc-status -a 2>/dev/null | awk '/started|running/ {print $1}' | sort -u | joinsemi)"
else
  SERV_ALL="$(service --status-all 2>/dev/null | awk '/\[[[:space:]]*\+[[:space:]]*\]/{print $4}' | sort -u | joinsemi)"
fi
SERV_CNT=0; [ -n "$SERV_ALL" ] && SERV_CNT=$(printf "%s" "$SERV_ALL" | awk -F';' '{print NF}')

# ---------- PACOTES + VERSÃO ----------
PKG_MGR=""; PKG_ALL=""
if command -v dpkg-query >/dev/null 2>&1; then
  PKG_MGR="dpkg"
  PKG_ALL="$(dpkg-query -W -f='${Package}=${Version}\n' 2>/dev/null | sort -u | joinsemi)"
elif command -v rpm >/dev/null 2>&1; then
  PKG_MGR="rpm"
  PKG_ALL="$(rpm -qa --qf '%{NAME}=%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -u | joinsemi)"
elif command -v apk >/dev/null 2>&1; then
  PKG_MGR="apk"
  PKG_ALL="$(apk info -v 2>/dev/null | sed 's/-r/=/; s/-[0-9].*=/=/' | sort -u | joinsemi)"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
  PKG_ALL="$(rpm -qa --qf '%{NAME}=%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -u | joinsemi)"
fi
PKG_CNT=0; [ -n "$PKG_ALL" ] && PKG_CNT=$(printf "%s" "$PKG_ALL" | awk -F';' '{print NF}')

# ---------- PYTHON ----------
PY_INST="no"; PY_VER=""
if command -v python3 >/dev/null 2>&1; then PY_INST="yes"; PY_VER="$(python3 -V 2>&1 | awk '{print $2}')"
elif command -v python  >/dev/null 2>&1; then PY_INST="yes"; PY_VER="$(python  -V 2>&1 | awk '{print $2}')"
fi

# ---------- ZABBIX ----------
ZB_INST="no"; ZB_VER=""
if command -v zabbix_agentd >/dev/null 2>&1; then ZB_INST="yes"; ZB_VER="$(zabbix_agentd -V 2>&1 | head -n1 | awk '{print $NF}')"
elif command -v zabbix_agent2 >/dev/null 2>&1; then ZB_INST="yes"; ZB_VER="$(zabbix_agent2 -V 2>/dev/null | head -n1 | awk '{print $NF}')"
elif systemctl list-unit-files 2>/dev/null | grep -q '^zabbix-agent'; then ZB_INST="yes"
elif pgrep -fa zabbix_agent >/dev/null 2>&1; then ZB_INST="yes"
fi

# ---------- QUALYS ----------
QL_INST="no"; QL_VER=""
if systemctl list-unit-files 2>/dev/null | grep -q '^qualys-cloud-agent'; then QL_INST="yes"; fi
if pgrep -fa qualys >/dev/null 2>&1 || pgrep -fa qagent >/dev/null 2>&1; then QL_INST="yes"; fi
if [ -x /usr/local/qualys/cloud-agent/bin/qagent ]; then
  V="$(/usr/local/qualys/cloud-agent/bin/qagent -v 2>&1 || true)"
  QL_VER="$(printf "%s" "$V" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
fi
if [ -z "$QL_VER" ] && command -v rpm >/dev/null 2>&1; then
  QL_VER="$(rpm -q --qf '%{VERSION}\n' qualys-cloud-agent 2>/dev/null | head -n1)"
fi
if [ -z "$QL_VER" ] && [ -r /etc/qualys/cloud-agent/qualys-cloud-agent.conf ]; then
  QL_VER="$(grep -E '^AGENT_VERSION=' /etc/qualys/cloud-agent/qualys-cloud-agent.conf 2>/dev/null | cut -d= -f2)"
fi

# ---------- JAVA ----------
JAVA_INST="no"; JAVA_VER=""; JAVA_HOME=""
# via binário
if command -v java >/dev/null 2>&1; then
  JAVA_INST="yes"
  JAVA_VER="$(java -version 2>&1 | head -n1 | awk -F\" '/version/ {print $2}' | awk '{print $1}')"
  JAVA_HOME="$(readlink -f "$(command -v java)" 2>/dev/null | sed 's#/bin/java##' || true)"
fi
# alternativas
if [ "$JAVA_INST" = "no" ] && command -v javac >/dev/null 2>&1; then
  JAVA_INST="yes"
  JAVA_VER="$(javac -version 2>&1 | awk '{print $2}')"
  JAVA_HOME="$(readlink -f "$(command -v javac)" 2>/dev/null | sed 's#/bin/javac##' || true)"
fi
# package-based hint
if [ "$JAVA_INST" = "no" ] && [ -n "$PKG_ALL" ]; then
  L="$(printf "%s" "$PKG_ALL" | tr '[:upper:]' '[:lower:]')"
  echo "$L" | grep -Eq '(^|;)openjdk|(^|;)java-1\.|(^|;)jdk|(^|;)jre' && JAVA_INST="yes"
  [ -z "$JAVA_VER" ] && JAVA_VER="$(printf "%s" "$L" | grep -Eo 'openjdk[0-9]{1,2}|java-1\.[0-9]' | head -n1 | sed -E 's/openjdk//; s/java-1\.([0-9])/\1/')"
fi

# ---------- PHP ----------
PHP_INST="no"; PHP_VER=""
if command -v php >/dev/null 2>&1; then
  PHP_INST="yes"
  PHP_VER="$(php -v 2>/dev/null | head -n1 | awk '{print $2}')"
elif command -v php-fpm >/dev/null 2>&1; then
  PHP_INST="yes"
  PHP_VER="$(php-fpm -v 2>/dev/null | head -n1 | awk '{print $2}')"
fi
if [ "$PHP_INST" = "no" ] && [ "$PKG_MGR" = "rpm" ]; then
  V="$(rpm -q --qf '%{VERSION}\n' php 2>/dev/null | head -n1)"; [ -n "$V" ] && PHP_INST="yes" && PHP_VER="$V"
fi
if [ "$PHP_INST" = "no" ] && [ "$PKG_MGR" = "dpkg" ]; then
  V="$(dpkg-query -W -f='${Version}\n' php 2>/dev/null | head -n1)"; [ -n "$V" ] && PHP_INST="yes" && PHP_VER="$V"
fi
if [ "$PHP_INST" = "no" ] && [ -n "$PKG_ALL" ]; then
  printf "%s" "$PKG_ALL" | tr '[:upper:]' '[:lower:]' | grep -Eq '(^|;)php($|[-;])' && PHP_INST="yes"
fi

# ---------- APACHE HTTPD ----------
AP_INST="no"; AP_VER=""; AP_FLAVOR=""; AP_SVC=""
if command -v httpd >/dev/null 2>&1; then
  AP_INST="yes"; AP_FLAVOR="httpd"; AP_SVC="$(systemctl list-units --type=service --all 2>/dev/null | awk '/httpd\.service/ {print $1}' | head -n1)"
  AP_VER="$(httpd -v 2>/dev/null | awk -F/ '/Server version/ {print $2}' | awk '{print $1}')"
elif command -v apache2 >/dev/null 2>&1; then
  AP_INST="yes"; AP_FLAVOR="apache2"; AP_SVC="$(systemctl list-units --type=service --all 2>/dev/null | awk '/apache2\.service/ {print $1}' | head -n1)"
  AP_VER="$(apache2 -v 2>/dev/null | awk -F/ '/Server version/ {print $2}' | awk '{print $1}')"
fi
if [ "$AP_INST" = "yes" ] && [ -z "$AP_VER" ]; then
  if [ "$PKG_MGR" = "rpm" ]; then
    AP_VER="$(rpm -q --qf '%{VERSION}\n' httpd 2>/dev/null | head -n1)"
  elif [ "$PKG_MGR" = "dpkg" ]; then
    AP_VER="$(dpkg-query -W -f='${Version}\n' apache2 2>/dev/null | head -n1)"
  elif [ "$PKG_MGR" = "apk" ]; then
    AP_VER="$(apk info -vv apache2 2>/dev/null | head -n1 | sed -E 's/.*-([0-9][^-]*)-.*/\1/')"
  fi
fi

# ---------- JBOSS / WILDFLY ----------
JB_INST="no"; JB_PROD=""; JB_VER=""; JB_HOME=""; JB_SVCS=""; JB_PIDS=""
# candidatos de HOME
CANDS=""
for d in "$JBOSS_HOME" "/opt/jboss" "/opt/wildfly" "/opt/jboss-eap" "/usr/share/wildfly" "/usr/share/jboss"; do
  [ -n "$d" ] && [ -d "$d" ] && CANDS="${CANDS}\n${d}"
done
# descobrir por processos
P_JB="$(ps -eo pid,comm,args 2>/dev/null | grep -Ei 'jboss|wildfly' | grep -v grep || true)"
if [ -n "$P_JB" ]; then
  JB_PIDS="$(printf "%s" "$P_JB" | awk '{print $1}' | tr '\n' ';' | sed 's/;*$//')"
  HINT="$(printf "%s" "$P_JB" | grep -Eo '/[^ ]*/(jboss[^ ]*|wildfly[^ ]*)' | awk -F'/bin' '{print $1}' | sort -u | head -n1)"
  [ -n "$HINT" ] && CANDS="${CANDS}\n${HINT}"
fi
# serviços
JB_SVCS="$(systemctl list-units --type=service --all 2>/dev/null | awk '/jboss|wildfly|eap/ {print $1}' | sort -u | tr '\n' ';' | sed 's/;*$//' )"
[ -n "$JB_SVCS" ] && JB_INST="yes"
# tentar homes
if [ -z "$JB_HOME" ] && [ -n "$CANDS" ]; then
  JB_HOME="$(printf "%b" "$CANDS" | sed '/^$/d' | head -n1)"
fi
# versão via CLI/manifests
if [ -n "$JB_HOME" ]; then
  if [ -x "$JB_HOME/bin/jboss-cli.sh" ]; then
    V="$("$JB_HOME/bin/jboss-cli.sh" --version 2>&1 | head -n1)"
    JB_VER="$(printf "%s" "$V" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1)"
    JB_PROD="$(printf "%s" "$V" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
  fi
  if [ -z "$JB_VER" ]; then
    MF="$(ls "$JB_HOME"/modules/system/layers/*/org/jboss/as/product/*/dir/META-INF/MANIFEST.MF 2>/dev/null | head -n1)"
    if [ -n "$MF" ]; then
      JB_PROD="$(grep -E 'JBoss-Product-Release-Name:' "$MF" 2>/dev/null | awk -F': ' '{print tolower($2)}' | head -n1)"
      JB_VER="$(grep -E 'JBoss-Product-Release-Version:' "$MF" 2>/dev/null | awk -F': ' '{print $2}' | head -n1)"
    fi
  fi
fi
[ -n "$JB_HOME$JB_SVCS$JB_PIDS" ] && JB_INST="yes"

# ---------- WEBSPHERE ----------
WS_INST="no"; WS_VER=""; WS_HOME=""
for d in "$WAS_HOME" "/opt/IBM/WebSphere/AppServer" "/opt/IBM/WebSphere/AppServer/profiles" "/opt/IBM/WebSphere"; do
  [ -n "$d" ] && [ -d "$d" ] && { WS_HOME="$d"; break; }
done
# processos
if ps -eo comm,args 2>/dev/null | grep -Ei 'websphere|com\.ibm\.ws\.' | grep -v grep >/dev/null 2>&1; then
  WS_INST="yes"
fi
# versionInfo.sh
if [ -z "$WS_VER" ]; then
  if [ -x "/opt/IBM/WebSphere/AppServer/bin/versionInfo.sh" ]; then
    VI="$(/opt/IBM/WebSphere/AppServer/bin/versionInfo.sh -product 2>/dev/null | head -n 50)"
    WS_VER="$(printf "%s" "$VI" | grep -Eo 'Version\s+[:=]\s*[0-9]+(\.[0-9]+)+' | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1)"
    WS_HOME="${WS_HOME:-/opt/IBM/WebSphere/AppServer}"
  elif [ -n "$WS_HOME" ] && [ -x "$WS_HOME/bin/versionInfo.sh" ]; then
    VI="$("$WS_HOME/bin/versionInfo.sh" -product 2>/dev/null | head -n 50)"
    WS_VER="$(printf "%s" "$VI" | grep -Eo 'Version\s+[:=]\s*[0-9]+(\.[0-9]+)+' | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1)"
  fi
fi
[ -n "$WS_HOME" ] && [ -z "$WS_INST" ] && WS_INST="yes"

# ---------- SAÍDA ----------
out_kv os_family "linux"
out_kv distro_id "${OS_ID}"
out_kv distro_pretty_name "${OS_PRETTY}"
out_kv distro_version_id "${OS_VER}"
out_kv kernel "${KERNEL}"
out_kv init_system "${INIT}"
out_kv services_running_count "${SERV_CNT}"
out_kv services_all "$(trimsemi "$SERV_ALL")"
out_kv pkg_manager "${PKG_MGR}"
out_kv pkg_count "${PKG_CNT}"
out_kv pkg_all "$(trimsemi "$PKG_ALL")"
out_kv python_installed "${PY_INST}"
out_kv python_version "${PY_VER}"
out_kv zabbix_agent_installed "${ZB_INST}"
out_kv zabbix_agent_version "${ZB_VER}"
out_kv qualys_agent_installed "${QL_INST}"
out_kv qualys_agent_version "${QL_VER}"
out_kv java_installed "${JAVA_INST}"
out_kv java_version "${JAVA_VER}"
out_kv java_home "${JAVA_HOME}"
out_kv php_installed "${PHP_INST}"
out_kv php_version "${PHP_VER}"
out_kv apache_installed "${AP_INST}"
out_kv apache_version "${AP_VER}"
out_kv apache_flavor "${AP_FLAVOR}"
out_kv apache_service "${AP_SVC}"
out_kv jboss_installed "${JB_INST}"
out_kv jboss_product "${JB_PROD}"
out_kv jboss_version "${JB_VER}"
out_kv jboss_home "${JB_HOME}"
out_kv jboss_services "${JB_SVCS}"
out_kv jboss_pids "${JB_PIDS}"
out_kv websphere_installed "${WS_INST}"
out_kv websphere_version "${WS_VER}"
out_kv websphere_home "${WS_HOME}"
'''

def parse_kv(text):
    res = {}
    for line in text.splitlines():
        if not line.strip() or "=" not in line: continue
        k,v = line.split("=",1)
        res[k.strip()] = v.strip()
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
    row = {k: "" for k in OUT_COLS}
    row.update({
        "hostname": h,
        "ip_address": ip,
        "status": "failed",
        "error": "",
        "collected_at": now_str(),
    })
    return row

def collect_one(entry, dflt, filter_ok, dbg):
    hostname = (entry.get(dflt["host_f"]) or "").strip()
    ipaddr   = (entry.get(dflt["ip_f"]) or "").strip()
    target   = ipaddr if ipaddr and is_ipv4(ipaddr) else (hostname if hostname else "")
    row = row_base(hostname, ipaddr)

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

    pre = tcp_probe(target, port, dflt["timeout"])
    if pre != "ok":
        row["status"]="failed"; row["error"]=f"tcp_{pre}"; return row

    last_err = ""
    for user in users:
        cmd = ssh_cmd(target, user, port, dflt["identity"], dflt["timeout"], dflt["strict"], dflt["legacy"])
        try:
            # +180s para rpm -qa e scans pesados
            p = run(cmd, dflt["timeout"] + 180, input_data=REMOTE_SCRIPT)
            if p.returncode == 0:
                kv = parse_kv(p.stdout)
                for k in OUT_COLS:
                    if k in kv: row[k] = kv.get(k,"")
                row["status"]="ok"; row["error"]=""
                return row
            else:
                last_err = (p.stderr or "").strip() or f"rc={p.returncode}"
                if dbg: dbg.write(f"{target} user={user} rc={p.returncode} err={last_err}\n")
                if re.search(r"permission denied|no supported authentication methods|too many authentication failures", last_err, re.I):
                    continue
                row["status"]="failed"; row["error"]=f"ssh_error:{last_err[:180]}"; return row
        except subprocess.TimeoutExpired:
            row["status"]="failed"; row["error"]="ssh_timeout"; return row
        except Exception as e:
            last_err = str(e)
            if dbg: dbg.write(f"{target} user={user} EXC={last_err}\n")
            if re.search(r"permission denied|authentication", last_err, re.I):
                continue
            row["status"]="failed"; row["error"]=f"ssh_exc:{last_err[:180]}"; return row

    row["status"]="failed"; row["error"]="auth_failed"; return row

def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLS); w.writeheader()
        for r in rows: w.writerow({k: r.get(k,"") for k in OUT_COLS})

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
            v = row.get(col,""); ws.write(r,c,v if v is not None else "")
    wb.close()

def parse_args():
    p = argparse.ArgumentParser(description="Perfil via SSH com listas completas e detecção Java/PHP/Apache/JBoss/WebSphere.")
    p.add_argument("--inventory", required=True, help="CSV/XLSX com hostname/ip; opcionais: ssh_user, ssh_port")
    p.add_argument("--connectivity-csv", help="CSV do ssh_connectivity_probe para filtrar status=connected")
    p.add_argument("--target-user", default="root", help="Usuário padrão")
    p.add_argument("--user-fallbacks", default=",".join(DEF_USERS), help="Fallbacks separados por vírgula")
    p.add_argument("--identity", help="Caminho da chave privada SSH")
    p.add_argument("--port", type=int, default=22, help="Porta padrão")
    p.add_argument("--timeout", type=int, default=12, help="Timeout por host (s)")
    p.add_argument("--workers", type=int, default=30, help="Concorrência")
    p.add_argument("--strict-known-hosts", action="store_true", help="StrictHostKeyChecking=accept-new")
    p.add_argument("--legacy-crypto", action="store_true", help="Algoritmos legados (+ssh-rsa,+dh-group14-sha1)")
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
