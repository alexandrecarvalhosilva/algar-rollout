#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
valida_dns_host_ip.py
Valida se o hostname "bate" com o IP:
 - Forward (A): se o IP informado está entre os A records do hostname
 - Reverse (PTR): se o PTR do IP corresponde ao hostname (ou ao FQDN do hostname)

Entrada: arquivo texto com linhas "hostname<tab/space>ip"
Saídas:
 - resultado_dns.csv (todas as linhas, com detalhes)
 - inconsistencias_dns.csv (apenas problemas)

Uso:
  python3 valida_dns_host_ip.py --in hosts.txt
  # pode colar a lista num arquivo 'hosts.txt' (um par por linha)

Dicas:
 - Aceita nomes curtos; você pode informar domínios de busca com --search-domains
 - Sem dependências externas (usa apenas biblioteca padrão)
"""

import argparse, csv, ipaddress, socket, sys, concurrent.futures as cf

def parse_pairs(path):
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        for ln, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            # separa por tab ou espaços múltiplos
            parts = [p for p in s.replace('\t', ' ').split(' ') if p]
            if len(parts) < 2:
                print(f"[WARN] Linha {ln}: esperado 'hostname ip' -> '{s}'", file=sys.stderr)
                continue
            host, ip = parts[0].strip(), parts[1].strip()
            try:
                ipaddress.ip_address(ip)
            except Exception:
                print(f"[WARN] Linha {ln}: IP inválido '{ip}'", file=sys.stderr)
                continue
            rows.append((host, ip))
    return rows

def normalize_host(h):
    return h.rstrip('.').lower()

def candidate_fqdns(host, search_domains):
    host = host.strip()
    out = set()
    if '.' in host:
        out.add(host)
    else:
        out.add(host)  # nome curto “puro”
        for d in search_domains:
            d = d.strip().strip('.')
            if d:
                out.add(f"{host}.{d}")
    # versões sem trailing dot + com trailing dot
    final = set()
    for h in out:
        final.add(h.rstrip('.'))
        final.add(h.rstrip('.') + '.')
    return list(final)

def resolve_A(hostnames, timeout):
    """Retorna set de IPv4 em string; tenta várias variantes de FQDN."""
    addrs = set()
    # socket timeout global (pode não afetar totalmente getaddrinfo, mas ajuda)
    old_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for h in hostnames:
            try:
                infos = socket.getaddrinfo(h, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
                for fam, st, pr, cname, sa in infos:
                    if sa and sa[0]:
                        addrs.add(sa[0])
            except Exception:
                pass
    finally:
        socket.setdefaulttimeout(old_to)
    return addrs

def resolve_PTR(ip, timeout):
    """Retorna set de nomes (canônico + aliases), normalizados (sem dot final, lower)."""
    names = set()
    old_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        try:
            cname, aliaslist, _ = socket.gethostbyaddr(ip)
            for n in [cname] + aliaslist:
                if n:
                    names.add(normalize_host(n))
        except Exception:
            pass
    finally:
        socket.setdefaulttimeout(old_to)
    return names

def check_one(host, ip, search_domains, dns_timeout):
    host_norm = normalize_host(host)
    # variantes para tentar no forward
    fqdns = candidate_fqdns(host_norm, search_domains)
    a_set = resolve_A(fqdns, dns_timeout)
    forward_ok = ip in a_set

    ptr_names = resolve_PTR(ip, dns_timeout)
    # aceita match exato ou “nome-curto + domínio” informado
    acceptable = {normalize_host(h) for h in fqdns}
    reverse_ok = any(n in acceptable for n in ptr_names) if ptr_names else False

    notes = []
    if not a_set:
        notes.append("sem_A")
    if not ptr_names:
        notes.append("sem_PTR")
    if a_set and not forward_ok:
        notes.append("forward_nao_bate")
    if ptr_names and not reverse_ok:
        notes.append("reverse_nao_bate")
    match = forward_ok and reverse_ok

    return {
        "hostname_input": host,
        "ip_input": ip,
        "forward_ok": str(forward_ok),
        "reverse_ok": str(reverse_ok),
        "match": str(match),
        "a_records": ";".join(sorted(a_set)) if a_set else "",
        "ptr_names": ";".join(sorted(ptr_names)) if ptr_names else "",
        "notes": ",".join(notes) if notes else ""
    }

def main():
    ap = argparse.ArgumentParser(description="Valida se hostname bate com IP (forward A e reverse PTR).")
    ap.add_argument("--in", required=True, dest="infile", help="Arquivo com linhas 'hostname<TAB/ESPACO>ip'")
    ap.add_argument("--out", default="resultado_dns.csv", help="CSV completo de saída")
    ap.add_argument("--out-bad", default="inconsistencias_dns.csv", help="CSV apenas com problemas")
    ap.add_argument("--search-domains", default="", help="Lista de domínios de busca separados por vírgula (ex: ctbc.com.br,network.ctbc)")
    ap.add_argument("--timeout", type=float, default=2.5, help="Timeout de DNS (s)")
    ap.add_argument("--workers", type=int, default=64, help="Threads paralelas")
    args = ap.parse_args()

    pairs = parse_pairs(args.infile)
    if not pairs:
        print("[ERRO] Nada para validar.", file=sys.stderr)
        sys.exit(2)

    search_domains = [d.strip() for d in args.search_domains.split(",") if d.strip()]
    results = []

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(check_one, h, ip, search_domains, args.timeout) for h, ip in pairs]
        for i, fut in enumerate(cf.as_completed(futs), 1):
            results.append(fut.result())
            if i % 200 == 0 or i == len(futs):
                print(f"[INFO] Processados {i}/{len(futs)}", file=sys.stderr)

    fields = ["hostname_input","ip_input","forward_ok","reverse_ok","match","a_records","ptr_names","notes"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow(r)

    bad = [r for r in results if r["match"] != "True"]
    with open(args.out_bad, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in bad:
            w.writerow(r)

    ok = len(results) - len(bad)
    print(f"[OK] Total={len(results)} | OK={ok} | Problemas={len(bad)}", file=sys.stderr)
    print(f"[OUT] {args.out} (completo), {args.out_bad} (inconsistências)", file=sys.stderr)

if __name__ == "__main__":
    main()
