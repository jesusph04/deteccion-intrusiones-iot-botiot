#!/bin/bash
# Resumen rapido del estado del honeypot y los datos acumulados
# Uso: bash check_progreso.sh

echo "========================================"
echo "  ESTADO DEL HONEYPOT - $(date)"
echo "========================================"

echo ""
echo "--- Procesos ---"
if pgrep -f "twistd.*cowrie" > /dev/null; then
    echo "Cowrie: CORRIENDO"
else
    echo "Cowrie: !! NO ESTA CORRIENDO !!"
fi

if pgrep -f "zeek -C -i" > /dev/null; then
    echo "Zeek:   CORRIENDO"
else
    echo "Zeek:   !! NO ESTA CORRIENDO !!"
fi

echo ""
echo "--- Espacio en disco ---"
df -h ~ | tail -1 | awk '{print "Usado: "$3" / "$2" ("$5")"}'

echo ""
echo "--- Sesiones capturadas por Cowrie (incluye logs rotados y comprimidos) ---"
COWRIE_DIR=/home/cowrie/cowrie/var/log/cowrie
total_sesiones=$(sudo sh -c "zgrep -c cowrie.session.connect $COWRIE_DIR/cowrie.json* 2>/dev/null" | awk -F: '{sum+=$2} END {print sum+0}')
if [ -z "$total_sesiones" ] || [ "$total_sesiones" = "0" ]; then
    echo "No se pudo leer ningun cowrie.json (revisa la ruta o los permisos)"
else
    logins_ok=$(sudo sh -c "zgrep -c cowrie.login.success $COWRIE_DIR/cowrie.json* 2>/dev/null" | awk -F: '{sum+=$2} END {print sum+0}')
    ips_unicas=$(sudo sh -c "zgrep -oh '\"src_ip\":\"[^\"]*\"' $COWRIE_DIR/cowrie.json* 2>/dev/null" | sort -u | wc -l)
    echo "Sesiones totales:   $total_sesiones"
    echo "Logins exitosos:    $logins_ok"
    echo "IPs origen unicas:  $ips_unicas"
fi

echo ""
echo "--- Flujos de red (Zeek) ---"
if [ -f ~/zeek_logs/conn.log ]; then
    total_flujos=$(wc -l < ~/zeek_logs/conn.log)
    flujos_honeypot=$(awk -F'\t' '$6==22 || $6==23' ~/zeek_logs/conn.log | wc -l)
    echo "Flujos totales (incluye trafico de fondo VM): $total_flujos"
    echo "Flujos al honeypot (puertos 22/23):           $flujos_honeypot"
else
    echo "No se encuentra conn.log"
fi

echo ""
echo "========================================"
