#!/usr/bin/env bash
set -euo pipefail
f=${1:-alcance_scan.csv}
[ -f "$f" ] || { echo "Arquivo $f não encontrado"; exit 1; }

total=$(awk -F, 'NR>1{c++}END{print c+0}' "$f")
icmp_ok=$(awk -F, 'NR>1&&$2=="True"{c++}END{print c+0}' "$f")
ssh_ok=$(awk -F, 'NR>1&&$3=="True"{c++}END{print c+0}' "$f")
both_ok=$(awk -F, 'NR>1&&$2=="True"&&$3=="True"{c++}END{print c+0}' "$f")
icmp_only=$(awk -F, 'NR>1&&$2=="True"&&$3=="False"{c++}END{print c+0}' "$f")
ssh_only=$(awk -F, 'NR>1&&$2=="False"&&$3=="True"{c++}END{print c+0}' "$f")
dead=$(awk -F, 'NR>1&&$2=="False"&&$3=="False"{c++}END{print c+0}' "$f")

py3=$(awk -F, 'NR>1&&$4 ~ /^Python 3\./{c++}END{print c+0}' "$f")
py27=$(awk -F, 'NR>1&&$4 ~ /^Python 2\.7/{c++}END{print c+0}' "$f")
py26=$(awk -F, 'NR>1&&$4 ~ /^Python 2\.6/{c++}END{print c+0}' "$f")
pyna=$(awk -F, 'NR>1&&$4=="n/a"{c++}END{print c+0}' "$f")

pct(){ awk -v n="$1" -v t="$2" 'BEGIN{printf "%.1f%%",(t?100*n/t:0)}'; }

ts=$(date '+%F %T')
{
  echo "RELATÓRIO DE ALCANCE - $ts"
  echo
  echo "Total de hosts: $total"
  echo "ICMP OK: $icmp_ok ($(pct "$icmp_ok" "$total"))"
  echo "SSH 22 aberto: $ssh_ok ($(pct "$ssh_ok" "$total"))"
  echo "ICMP+SSH OK: $both_ok ($(pct "$both_ok" "$total"))"
  echo "Somente ICMP: $icmp_only ($(pct "$icmp_only" "$total"))"
  echo "Somente SSH: $ssh_only ($(pct "$ssh_only" "$total"))"
  echo "Sem ICMP e SSH: $dead ($(pct "$dead" "$total"))"
  echo
  echo "Python 3.x: $py3"
  echo "Python 2.7.x: $py27"
  echo "Python 2.6.x: $py26"
  echo "Sem Python (n/a): $pyna"
} > relatorio_gerencial.txt

# Listas por categoria (para anexar/usar em playbooks)
awk -F, 'NR>1&&$2=="True"{print $1}' "$f" > lista_icmp_ok.txt
awk -F, 'NR>1&&$2=="False"{print $1}' "$f" > lista_icmp_fail.txt
awk -F, 'NR>1&&$3=="True"{print $1}' "$f" > lista_ssh_ok.txt
awk -F, 'NR>1&&$3=="False"{print $1}' "$f" > lista_ssh_fail.txt
awk -F, 'NR>1&&$2=="True"&&$3=="True"{print $1}' "$f" > lista_full_ok.txt
awk -F, 'NR>1&&$2=="True"&&$3=="False"{print $1}' "$f" > lista_icmp_only.txt
awk -F, 'NR>1&&$2=="False"&&$3=="True"{print $1}' "$f" > lista_ssh_only.txt
awk -F, 'NR>1&&$2=="False"&&$3=="False"{print $1}' "$f" > lista_dead.txt
awk -F, 'NR>1&&$4 ~ /^Python 2\.6/{print $1}' "$f" > lista_py26.txt
awk -F, 'NR>1&&$4=="n/a"{print $1}' "$f" > lista_py_na.txt

echo "Arquivos gerados:"
ls -1 relatorio_gerencial.txt lista_*.txt
