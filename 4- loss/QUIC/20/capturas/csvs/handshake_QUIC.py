#!/usr/bin/env python3
import csv
import os
import re
from collections import defaultdict

# --- Rutas ------------------------------------------------------------------
directorio_entrada = '.'          # Cámbialo si lo necesitas
directorio_salida  = '.'          # Puede ser el mismo
os.makedirs(directorio_salida, exist_ok=True)

# --- Expresiones regulares --------------------------------------------------
patron_nombre = re.compile(r"SIG_ALG=(.+?) and KEM_ALG=(.+?)\.csv")

# --- Detección de fases y fin de handshake QUIC -----------------------------
def es_initial(info: str) -> bool:
    return 'Initial' in info

# El fin se detecta cuando es "Protected Payload" SIN campo DCID=
def es_end_quic(info: str) -> bool:
    return 'Protected Payload' in info and 'DCID=' not in info

# --- Orden personalizado de KEM ---------------------------------------------
def orden_kem(kem: str):
    kem = kem.lower()
    if '_' in kem:
        return (2, kem)
    elif kem.startswith('p'):
        return (0, kem)
    elif kem.startswith('x'):
        return (1, kem)
    elif 'mlkem' in kem:
        return (3, kem)
    else:
        return (4, kem)

# --- Estructura para ir almacenando resultados ------------------------------
# { sig_alg: [ [kem_alg, handshake_id, bytes_total], … ] }
agrupado_por_firma = defaultdict(list)

# --- Procesamiento de todos los CSV de entrada ------------------------------
for nombre_csv in os.listdir(directorio_entrada):
    if not nombre_csv.endswith('.csv'):
        continue

    m = patron_nombre.match(nombre_csv)
    if not m:
        continue
    sig_alg, kem_alg = m.groups()
    ruta_csv = os.path.join(directorio_entrada, nombre_csv)

    with open(ruta_csv, newline='', encoding='utf-8') as f:
        lector = csv.DictReader(f)

        dentro = False
        handshake_id = 0
        bytes_total = 0

        for fila in lector:
            info  = fila.get('_ws.col.info', '')
            proto = fila.get('_ws.col.protocol', '')
            try:
                length = int(fila.get('frame.len', 0))
            except ValueError:
                continue

            # Inicio de handshake: paquete Initial QUIC
            if not dentro and proto == 'QUIC' and es_initial(info):
                dentro = True
                handshake_id += 1
                bytes_total = length
                continue

            # Dentro de handshake: acumulamos todos los paquetes QUIC
            if dentro and proto == 'QUIC':
                bytes_total += length
                # Detectar fin de handshake
                if es_end_quic(info):
                    agrupado_por_firma[sig_alg].append(
                        [kem_alg, handshake_id, bytes_total]
                    )
                    dentro = False

# --- Escribir un CSV por algoritmo de firma ---------------------------------
for sig_alg, filas in agrupado_por_firma.items():
    filas_ordenadas = sorted(filas, key=lambda x: (orden_kem(x[0]), x[1]))

    salida = os.path.join(directorio_salida, f"{sig_alg}_quic_handshakes.csv")
    with open(salida, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['KEM_ALG', 'Handshake_ID', 'Bytes_Total'])
        w.writerows(filas_ordenadas)

    print(f"Archivo generado: {salida}")
