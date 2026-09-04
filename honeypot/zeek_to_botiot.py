"""
zeek_to_botiot.py
=================

Convierte el conn.log generado por Zeek (a partir del trafico capturado
en tu honeypot) al mismo esquema de 9 features que usaste para entrenar
tus modelos sobre BoT-IoT:

    pkts, bytes, spkts, dpkts, sbytes, dbytes, rate, srate, drate

y opcionalmente aplica el MinMaxScaler + modelo ya entrenados (guardados
con joblib) para obtener predicciones sobre el trafico real capturado.

------------------------------------------------------------------------
MAPEO DE CAMPOS (Zeek conn.log -> features BoT-IoT/Argus)
------------------------------------------------------------------------
    spkts  = orig_pkts                  (paquetes origen->destino)
    dpkts  = resp_pkts                  (paquetes destino->origen)
    sbytes = orig_ip_bytes              (bytes IP origen->destino, con cabeceras)
    dbytes = resp_ip_bytes              (bytes IP destino->origen, con cabeceras)
    pkts   = spkts + dpkts
    bytes  = sbytes + dbytes
    rate   = pkts  / duration
    srate  = spkts / duration
    drate  = dpkts / duration

NOTA METODOLOGICA (para tu memoria): Argus calcula bytes/paquetes de forma
muy similar a los campos *_ip_bytes / *_pkts de Zeek, pero no son
identicos byte a byte (distintos criterios de que cuenta como "paquete
retransmitido", por ejemplo). Es una aproximacion razonable y debes
declararla como tal en la seccion de metodologia, no como una
reproduccion exacta del pipeline original de Argus.

------------------------------------------------------------------------
USO
------------------------------------------------------------------------
1) Solo extraer features a CSV:
   python3 zeek_to_botiot.py --conn-log conn.log --output features.csv

2) Extraer features + predecir con un modelo sklearn ya entrenado
   (Random Forest, XGBoost, SVM), asumiendo que guardaste scaler y
   modelo con joblib.dump(...):
   python3 zeek_to_botiot.py --conn-log conn.log \
       --scaler scaler.pkl --model rf_model.pkl \
       --output predicciones.csv

3) Extraer features + predecir con el modelo hibrido autoencoder+XGBoost
   (encoder guardado en .h5/.keras, XGBoost guardado en .pkl/.json):
   python3 zeek_to_botiot.py --conn-log conn.log \
       --scaler scaler.pkl --encoder encoder.h5 --model xgb_on_latent.pkl \
       --output predicciones.csv
"""

import argparse
import sys

import numpy as np
import pandas as pd

# Orden EXACTO usado en el TFG (secc. 3.2.3 / 4.0.4). El orden de columnas
# debe coincidir con el que viste al entrenar, o el modelo interpretara
# cada columna como otra distinta sin avisarte con ningun error.
FEATURE_ORDER = ["pkts", "bytes", "spkts", "dpkts", "sbytes", "dbytes", "rate", "srate", "drate"]

# Columnas de conn.log que realmente necesitamos leer (todas las demas se
# descartan al vuelo para no gastar memoria en datos que no usamos).
NEEDED_COLS = {
    "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "service", "proto",
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes",
}


def _to_float(value: str) -> float:
    if value in ("-", "", None):
        return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0


def stream_zeek_conn_log(path: str, keep_dst_ports=None, progress_every=1_000_000):
    """Lee conn.log LINEA A LINEA (nunca carga el fichero entero en
    memoria) y va calculando las 9 features al vuelo. Si keep_dst_ports
    se indica, descarta inmediatamente cualquier fila cuyo puerto de
    destino no este en ese conjunto, ANTES de guardar nada en memoria --
    esto es lo que permite procesar ficheros de varios GB en una VM con
    solo 1GB de RAM: de los millones de lineas totales, normalmente solo
    unas decenas de miles son del honeypot, y son las unicas que se
    acumulan en la lista de resultados.

    Devuelve una lista de dicts (una por conexion conservada).
    """
    keep_ports = set(int(p) for p in keep_dst_ports) if keep_dst_ports else None

    results = []
    columns = None
    col_index = {}
    n_total = 0
    n_kept = 0

    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                columns = line.rstrip("\n").split("\t")[1:]
                col_index = {name: i for i, name in enumerate(columns)}
                continue
            if line.startswith("#") or not line.strip():
                continue
            if columns is None:
                continue  # no deberia pasar, pero por seguridad

            n_total += 1
            if progress_every and n_total % progress_every == 0:
                print(f"  ... {n_total:,} lineas leidas, {n_kept:,} conservadas hasta ahora", file=sys.stderr)

            parts = line.rstrip("\n").split("\t")
            if len(parts) < len(columns):
                continue  # linea corrupta/incompleta, se descarta

            def field(name):
                idx = col_index.get(name)
                if idx is None or idx >= len(parts):
                    return "-"
                return parts[idx]

            dst_port_raw = field("id.resp_p")
            if keep_ports is not None:
                try:
                    dst_port = int(dst_port_raw)
                except ValueError:
                    continue
                if dst_port not in keep_ports:
                    continue

            duration = _to_float(field("duration"))
            orig_pkts = _to_float(field("orig_pkts"))
            resp_pkts = _to_float(field("resp_pkts"))
            orig_ip_bytes = _to_float(field("orig_ip_bytes"))
            resp_ip_bytes = _to_float(field("resp_ip_bytes"))

            pkts = orig_pkts + resp_pkts
            byts = orig_ip_bytes + resp_ip_bytes
            if duration > 0:
                rate = pkts / duration
                srate = orig_pkts / duration
                drate = resp_pkts / duration
            else:
                rate = srate = drate = 0.0

            results.append({
                "_ts": field("ts"),
                "_src_ip": field("id.orig_h"),
                "_src_port": field("id.orig_p"),
                "_dst_ip": field("id.resp_h"),
                "_dst_port": dst_port_raw,
                "_service": field("service"),
                "_proto": field("proto"),
                "pkts": pkts, "bytes": byts,
                "spkts": orig_pkts, "dpkts": resp_pkts,
                "sbytes": orig_ip_bytes, "dbytes": resp_ip_bytes,
                "rate": rate, "srate": srate, "drate": drate,
            })
            n_kept += 1

    print(f"  {n_total:,} lineas de datos leidas en total, {n_kept:,} conservadas", file=sys.stderr)
    return results


def results_to_dataframe(results: list) -> pd.DataFrame:
    """Convierte la lista de dicts (ya filtrada y con features calculadas)
    en un DataFrame, con las columnas en el orden habitual."""
    if not results:
        cols = ["_ts", "_src_ip", "_src_port", "_dst_ip", "_dst_port", "_service", "_proto"] + FEATURE_ORDER
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(results)
    return df[["_ts", "_src_ip", "_src_port", "_dst_ip", "_dst_port", "_service", "_proto"] + FEATURE_ORDER]


def build_feature_matrix(features_df: pd.DataFrame) -> np.ndarray:
    """Extrae SOLO las 9 columnas del modelo, en el orden correcto."""
    missing = [c for c in FEATURE_ORDER if c not in features_df.columns]
    if missing:
        raise ValueError(f"Faltan columnas requeridas por el modelo: {missing}")
    return features_df[FEATURE_ORDER].to_numpy(dtype=float)


def predict_sklearn(features_df: pd.DataFrame, scaler_path: str, model_path: str) -> np.ndarray:
    """Para Random Forest / XGBoost sklearn-API / SVM guardados con joblib."""
    import joblib
    scaler = joblib.load(scaler_path)
    model = joblib.load(model_path)
    X = build_feature_matrix(features_df)
    X_scaled = scaler.transform(X)
    return model.predict(X_scaled)


def predict_autoencoder_xgb(features_df: pd.DataFrame, scaler_path: str,
                             encoder_path: str, xgb_path: str) -> np.ndarray:
    """Para la propuesta hibrida: escala -> pasa por el encoder -> XGBoost
    sobre el espacio latente."""
    import joblib
    from tensorflow import keras

    scaler = joblib.load(scaler_path)
    encoder = keras.models.load_model(encoder_path)
    xgb_model = joblib.load(xgb_path)

    X = build_feature_matrix(features_df)
    X_scaled = scaler.transform(X)
    X_latent = encoder.predict(X_scaled, verbose=0)
    return xgb_model.predict(X_latent)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--conn-log", required=True, help="Ruta al conn.log de Zeek")
    parser.add_argument("--output", required=True, help="CSV de salida (features y, si aplica, predicciones)")
    parser.add_argument("--scaler", help="Ruta al MinMaxScaler guardado con joblib")
    parser.add_argument("--model", help="Ruta al modelo sklearn (RF/XGBoost/SVM) o al XGBoost del hibrido")
    parser.add_argument("--encoder", help="Ruta al encoder del autoencoder (.h5/.keras), solo para el modelo hibrido")
    parser.add_argument("--honeypot-ports", default="22,23",
                         help="Puertos de destino a conservar (separados por comas). "
                              "Excluye el trafico de fondo de la propia VM (metadata, DNS, etc). "
                              "Usa --honeypot-ports '' para desactivar el filtro y quedarte con todo "
                              "(cuidado: sin filtro, en un conn.log grande puede agotar la RAM).")
    args = parser.parse_args()

    keep_ports = None
    if args.honeypot_ports.strip():
        keep_ports = [p.strip() for p in args.honeypot_ports.split(",") if p.strip()]

    print(f"Leyendo {args.conn_log} (procesado linea a linea, sin cargar todo el fichero en RAM) ...")
    if keep_ports:
        print(f"  Filtrando en tiempo real por puertos de destino: {keep_ports}")
    results = stream_zeek_conn_log(args.conn_log, keep_dst_ports=keep_ports)
    features = results_to_dataframe(results)
    print(f"  {len(features)} conexiones finales")

    if args.scaler and args.model:
        if args.encoder:
            print("Prediciendo con modelo hibrido autoencoder + XGBoost ...")
            preds = predict_autoencoder_xgb(features, args.scaler, args.encoder, args.model)
        else:
            print("Prediciendo con modelo sklearn (RF / XGBoost / SVM) ...")
            preds = predict_sklearn(features, args.scaler, args.model)
        features["prediccion"] = preds

    features.to_csv(args.output, index=False)
    print(f"Guardado en {args.output}")


if __name__ == "__main__":
    main()
