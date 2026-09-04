# Detección de intrusiones en redes IoT: análisis comparativo de modelos ML sobre el dataset BoT-IoT

Código fuente del Trabajo Fin de Grado — Grado en Ingeniería Informática,
Universidad de Granada.

**Autor:** Jesús Pertíñez Hidalgo
**Director:** Gustavo Romero López
**Curso:** 2025/2026

## Descripción

Este trabajo compara cuatro modelos de aprendizaje automático (Random Forest,
XGBoost, SVM y una propuesta híbrida autoencoder + XGBoost) para la detección
de intrusiones en redes IoT sobre el dataset [BoT-IoT](https://research.unsw.edu.au/projects/bot-iot-dataset).
Como aportación principal, los modelos ya entrenados se validan externamente
frente a tráfico de ataque real, capturado de forma independiente mediante un
honeypot propio (Cowrie + Zeek) desplegado en Google Cloud Platform durante
siete días.

## Estructura del repositorio

```
├── notebooks/
│   ├── pipeline_botiot_modelos.ipynb   Preprocesamiento, entrenamiento y
│   │                                    evaluación de los 4 modelos sobre BoT-IoT
│   └── validacion_honeypot.ipynb       Aplicación de los modelos ya entrenados
│                                        sobre el tráfico real del honeypot
├── honeypot/
│   ├── zeek_to_botiot.py               Transforma el conn.log de Zeek al
│   │                                    esquema de 9 características de BoT-IoT
│   ├── check_progreso.sh               Monitorización del honeypot desplegado
│   └── despliegue.md                   Comandos de configuración de la
│                                        infraestructura (Cowrie, Zeek, NAT, firewall)
│                                        
├── requirements.txt
└── LICENSE
```

## Notebooks

**`pipeline_botiot_modelos.ipynb`** — Pipeline completo sobre BoT-IoT:
combinación incremental de los 75 CSV originales, limpieza, muestreo
estratificado, normalización Min-Max, balanceo con SMOTE, entrenamiento de
los cuatro modelos en clasificación binaria y multiclase, exportación de los
modelos, y el análisis comparativo de distribuciones entre BoT-IoT y el
tráfico del honeypot.

**`validacion_honeypot.ipynb`** — Carga los modelos ya entrenados y los
aplica, sin reentrenamiento, sobre el `features.csv` generado a partir del
honeypot, calculando el recall sobre tráfico real nunca visto durante el
entrenamiento.

## Honeypot

El despliegue completo (instancia GCP, Cowrie, Zeek, reglas de firewall y
NAT) está documentado paso a paso en [`honeypot/despliegue.md`](honeypot/despliegue.md).
El script [`honeypot/zeek_to_botiot.py`](honeypot/zeek_to_botiot.py) convierte
los registros de conexión de Zeek al mismo esquema de características
empleado para entrenar los modelos; puede usarse de forma independiente:

```bash
python3 zeek_to_botiot.py --conn-log conn.log --output features.csv
```

## Dataset

El dataset BoT-IoT **no se incluye** en este repositorio, por su tamaño y por
las condiciones de uso académico bajo las que se distribuye. Está disponible
públicamente en:
https://research.unsw.edu.au/projects/bot-iot-dataset

## Cómo ejecutar

1. Instala las dependencias: `pip install -r requirements.txt`
2. Descarga el dataset BoT-IoT desde el enlace anterior
3. Ajusta las rutas de carga de datos en los notebooks a tu propio entorno
   (fueron desarrollados en Google Colab con el dataset montado desde Google
   Drive — verás celdas con `drive.mount(...)` y rutas de tipo
   `/content/drive/MyDrive/...` que deben adaptarse si ejecutas en local)
4. Ejecuta `notebooks/pipeline_botiot_modelos.ipynb` de principio a fin
5. Para la validación con honeypot, necesitas tu propio `conn.log` de Zeek
   (o el `features.csv` ya extraído) y ejecutar `validacion_honeypot.ipynb`

## Licencia

Este proyecto se distribuye bajo licencia MIT — ver [`LICENSE`](LICENSE).

## Cómo citar

Si utilizas este código, por favor cita el TFG correspondiente:

> Pertíñez Hidalgo, J. (2026). *Detección de intrusiones en redes IoT: análisis
> comparativo de modelos ML sobre el dataset BoT-IoT* [Trabajo Fin de Grado,
> Universidad de Granada].
