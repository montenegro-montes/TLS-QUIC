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

def es_syn(info: str) -> bool:
    """
    Devuelve True para el SYN que inicia la conexión.
    Se descarta '[SYN, ACK]' y se evita el falso positivo de la palabra 'SACK_PERM'.
    """
    return '[SYN]' in info and '[SYN, ACK]' not in info

def es_fin(info: str) -> bool:
    """Paquete que cierra la conexión según el patrón solicitado."""
    return '[RST, ACK]' in info

# --- Orden personalizado de los KEM ----------------------------------------
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

# --- Estructura para ir acumulando ------------------------------------------
# {sig_alg: [[KEM_ALG, handshake_id, bytes_tcp, bytes_tls, bytes_total], …]}
agrupado_por_firma = defaultdict(list)

# --- Recorremos todos los CSV de captura ------------------------------------
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

        dentro_handshake = False
        handshake_id     = 0
        suma_tcp = suma_tls = 0

        for fila in lector:
            info   = fila['_ws.col.info']
            proto  = fila['_ws.col.protocol']

            try:
                longitud = int(fila['frame.len'])
            except ValueError:
                continue  # salta entradas mal formateadas

            # --- Detectar inicio ------------------------------------------------
            if not dentro_handshake and es_syn(info):
                dentro_handshake = True
                handshake_id    += 1
                suma_tcp = suma_tls = 0      # reinicio contadores

            # --- Acumular mientras estamos dentro ------------------------------
            if dentro_handshake:
                if proto == 'TCP':
                    suma_tcp += longitud
                elif proto in ('TLSv1.3', 'TLSv1.2','SSL'):  
                    suma_tls += longitud

                # --- Detectar fin ----------------------------------------------
                if es_fin(info):
                    total = suma_tcp + suma_tls
                    agrupado_por_firma[sig_alg].append(
                        [kem_alg, handshake_id, suma_tcp, suma_tls, total]
                    )
                    dentro_handshake = False  # listos para el siguiente

# --- Escribir un CSV por algoritmo de firma ---------------------------------
for sig_alg, filas in agrupado_por_firma.items():
    filas_ordenadas = sorted(filas, key=lambda x: (orden_kem(x[0]), x[1]))

    salida = os.path.join(directorio_salida, f"{sig_alg}_handshakes.csv")
    with open(salida, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['KEM_ALG', 'Handshake_ID', 'Bytes_TCP', 'Bytes_TLS', 'Bytes_Total'])
        w.writerows(filas_ordenadas)

    print(f"Archivo generado: {salida}")
