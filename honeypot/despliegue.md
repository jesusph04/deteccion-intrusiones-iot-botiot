# Despliegue del honeypot — comandos de referencia

Este documento recoge los comandos empleados para desplegar el honeypot descrito
en la sección 4.2 de la memoria. No es un script de un solo uso: son los pasos
de configuración de la infraestructura, pensados para consultarse y adaptarse,
no para ejecutarse de un tirón sin revisar cada paso.

## 1. Creación de la instancia (Google Cloud Platform)

Instancia `e2-micro` (capa gratuita), región `us-west1-b`, Ubuntu 24.04 LTS,
disco persistente estándar de 30GB:

```bash
gcloud compute instances create honeypot-tfg \
    --zone=us-west1-b \
    --machine-type=e2-micro \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=30GB \
    --boot-disk-type=pd-standard
```

## 2. Reglas de firewall (VPC)

Dos reglas independientes: una para el acceso administrativo (puerto no
estándar 2200) y otra para el tráfico público que recibirá el honeypot
(puertos 22 y 23):

```bash
gcloud compute firewall-rules create allow-ssh-admin \
    --allow=tcp:2200 \
    --description="Acceso SSH administrativo en puerto no estandar"

gcloud compute firewall-rules create allow-honeypot \
    --allow=tcp:22,tcp:23 \
    --description="Trafico publico dirigido al honeypot Cowrie"
```

## 3. Aislamiento del SSH administrativo (Ubuntu 24.04 — socket activation)

Ubuntu 24.04 gestiona `sshd` mediante activación por socket de `systemd`, así
que el puerto adicional se añade con un fichero de *drop-in* en vez de editar
`sshd_config` directamente:

```bash
sudo mkdir -p /etc/systemd/system/ssh.socket.d
sudo tee /etc/systemd/system/ssh.socket.d/override.conf > /dev/null <<'EOF'
[Socket]
ListenStream=2200
EOF

sudo systemctl daemon-reload
sudo systemctl restart ssh.socket

# Verificacion: deberia aparecer escuchando en 22 (heredado) y 2200 (nuevo)
sudo ss -tlnp | grep ssh
```

## 4. Instalación y configuración de Cowrie

Cowrie se ejecuta bajo un usuario del sistema sin privilegios de
administración, dedicado en exclusiva a este servicio:

```bash
sudo adduser --disabled-password cowrie
sudo su - cowrie

git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configuracion: puertos no privilegiados 2222 (SSH) y 2223 (Telnet)
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Editar etc/cowrie.cfg:
#   [ssh]    listen_endpoints = tcp:2222:interface=0.0.0.0
#   [telnet] listen_endpoints = tcp:2223:interface=0.0.0.0

bin/cowrie start
```

## 5. Redirección NAT (iptables)

El tráfico real dirigido a los puertos estándar (22/23) se redirige a los
puertos no privilegiados donde escucha Cowrie (2222/2223):

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Persistir las reglas tras un reinicio
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

## 6. Instalación y arranque de Zeek

Zeek 8.2.1, compilado/instalado en `/opt/zeek`. Se ejecuta de forma continua
sobre la interfaz de red pública de la instancia (`ens4` en este despliegue):

```bash
mkdir -p ~/zeek_logs

# IMPORTANTE: el flag -C es obligatorio en este entorno. Sin el, todo el
# trafico de RESPUESTA aparece con 0 paquetes/bytes, porque la NIC virtual
# de GCP delega el calculo de checksum a hardware (offload) y Zeek, al
# capturar el paquete antes de ese calculo, lo interpreta como corrupto
# y lo descarta. Ver seccion 4.2.2 de la memoria para el detalle completo.
screen -dmS zeek bash -c "cd ~/zeek_logs && sudo /opt/zeek/bin/zeek -C -i ens4 local"

# Verificar que esta corriendo
pgrep -f "zeek -C -i"
```

## 7. Acceso administrativo tras el despliegue

Una vez aplicado el override del paso 3, el acceso SSH de administración se
hace explícitamente por el puerto 2200, nunca por el 22 (que a partir de este
punto queda redirigido al honeypot):

```bash
gcloud compute ssh honeypot-tfg --zone=us-west1-b -- -p 2200
```

## 8. Monitorización

Ver `check_progreso.sh` en este mismo repositorio para el script de
comprobación del estado del honeypot (procesos activos, espacio en disco,
sesiones capturadas por Cowrie, flujos registrados por Zeek).

---

**Nota de reproducibilidad:** los pasos 1 y 2 (creación de instancia y reglas
de firewall) reproducen las especificaciones descritas en la sección 4.2 de
la memoria (instancia `e2-micro`, región `us-west1-b`, disco de 30GB), pero
no son una transcripción literal de los comandos ejecutados en su momento.
Los pasos 3 a 6 sí corresponden a la configuración exacta empleada,
verificada frente a los registros y capturas de pantalla generados durante
el despliegue real.
