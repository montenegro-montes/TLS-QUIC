import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import re

# Path where the CSV files are stored
folder = '.'  # Current directory

# Collect dataframes
dataframes = []

# Regex to parse file names like: secp521r1_quic_delay10.csv
pattern = re.compile(r'(?P<sigalg>[^_]+)_(?P<protocol>[^_]+)_delay(?P<delay>\d+)\.csv')

for filename in os.listdir(folder):
    match = pattern.match(filename)
    if match:
        sigalg = match.group('sigalg')
        protocol = match.group('protocol')
        delay = int(match.group('delay'))
        filepath = os.path.join(folder, filename)

        df = pd.read_csv(filepath)
        
        # Conservar el orden original de las columnas
        kem_columns = [col for col in df.columns if col not in ['Signature', 'Protocol', 'Delay (ms)']]
        
        # Hacer melt solo de las columnas que no son de protocolo, firma o delay
        df_long = df.melt(id_vars=[], value_vars=kem_columns, var_name='KEM', value_name='Handshake Time (ms)')


        # Establecer el orden categórico de 'KEM' basado en el orden original del CSV
        df_long['KEM'] = pd.Categorical(df_long['KEM'], categories=kem_columns, ordered=True)


        df_long['Delay (ms)'] = delay
        df_long['Signature'] = sigalg
        df_long['Protocol'] = protocol
        dataframes.append(df_long)

# Combine all data
df_total = pd.concat(dataframes, ignore_index=True)

# Sort delays for consistent x-axis ordering
df_total = df_total.sort_values(by='Delay (ms)')

Q1 = df_total['Handshake Time (ms)'].quantile(0.25)
Q3 = df_total['Handshake Time (ms)'].quantile(0.75)
IQR = Q3 - Q1

# Filtrado: entre Q1 - 1.5*IQR y Q3 + 1.5*IQR
df_filtered = df_total[
    (df_total['Handshake Time (ms)'] >= Q1 - 1.5 * IQR) &
    (df_total['Handshake Time (ms)'] <= Q3 + 1.5 * IQR)
]

# Plot violin plot
plt.figure(figsize=(14, 6))
sns.violinplot(
    x='Delay (ms)',
    y='Handshake Time (ms)',
    hue='KEM',
    data=df_filtered,
    palette='Set2',     # Colores suaves y diferenciables
    cut=0,              # Limita el violín al rango de datos
    inner='box',        # Muestra la caja dentro del violín (mediana y cuartiles)
    #scale='width',      # Hace que todos los violines tengan el mismo ancho base
    bw=0.2,             # Controla el suavizado de la curva de densidad
    linewidth=1,        # Grosor del contorno
    saturation=1        # Intensidad del color (1 = completa)
)

# Get unique signature and protocol from data
sig_used = df_total['Signature'].unique()[0]
proto_used = df_total['Protocol'].unique()[0]


plt.title(f'Handshake Time by KEM and Network Delay - {sig_used.upper()} over {proto_used.upper()}')
plt.legend(title='KEM Algorithm', loc='upper left',title_fontsize=14)
plt.grid(True)
plt.tight_layout()

# Save the plot with protocol and signature name
plt.savefig(f"{proto_used}_delays_{sig_used}.pdf", dpi=300, bbox_inches='tight')
plt.show()
