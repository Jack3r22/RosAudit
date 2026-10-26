# Auditoría MikroTik (read-only)

Auditoría de configuración para RouterOS 6.x/7.x vía API. **Solo ejecuta comandos
`/print`**: no modifica configuración, no reinicia y no corta tráfico ni sesiones.

## Uso rápido

```bash
rosaudit
```

Pregunta por pantalla host, usuario, contraseña, formato y carpeta de salida, y al
terminar abre el PDF. Recuerda los últimos valores (nunca la contraseña).

Modo clásico con argumentos:

```bash
rosaudit --host 192.168.18.2 --user auditor --ask-pass --pdf ~/auditoria.pdf
```

## 0. Instalar el comando `rosaudit`

```bash
cp rosaudit ~/.local/bin/rosaudit   # ya está instalado en ~/.local/bin
chmod +x ~/.local/bin/rosaudit
```

El lanzador usa `~/venv/ros/bin/python` y `~/mikrotik-audit/audit_ros.py`. Si mueves
el proyecto: `ROSAUDIT_SCRIPT=/ruta/audit_ros.py rosaudit`.

## 1. Instalación

```bash
python3 -m venv ~/venv/ros
~/venv/ros/bin/pip install librouteros
```

Probado con `librouteros 4.2.2` y Python 3.13.

## 2. Usuario de solo lectura en el router

```routeros
/user group add name=auditor policy=read,api
/user add name=auditor group=auditor password=<fuerte> address=<tu-ip>/32
/ip service enable api
```

`policy=read,api` es suficiente: `read` permite `/print` y `api` permite autenticarse
por la API. No necesita `write`, `sensitive` ni `policy`.

## 3. Conexión

### 3.1 Directa (recomendada si lanzas desde la red de gestión)

```routeros
/ip service enable api
/ip service set api address=192.168.18.0/24
/user set auditor address=192.168.18.0/24
```

```bash
~/venv/ros/bin/python audit_ros.py --host 192.168.18.2 --user auditor --ask-pass
```

La API en 8728 no cifra. Es aceptable en una VLAN de gestión aislada; no lo es
cruzando Internet o una red compartida.

### 3.2 Túnel SSH (si sales de la LAN o no quieres abrir 8728)

```routeros
/ip service set api address=127.0.0.1
/user set auditor address=127.0.0.1
```

```bash
ssh -f -N -L 8728:127.0.0.1:8728 admin@192.168.18.2
~/venv/ros/bin/python audit_ros.py --host 127.0.0.1 --user auditor --ask-pass
```

Así las credenciales no viajan en claro y la API solo escucha en loopback.
Ojo: con túnel el origen que ve la API es `127.0.0.1`, por eso el `address=` cambia.

### 3.3 API-SSL (cifrado sin SSH)

Requiere un certificado asignado a `api-ssl`:

```routeros
/certificate add name=api-cert common-name=192.168.18.2 days-valid=3650 key-usage=tls-server
/certificate sign api-cert
/ip service set api-ssl certificate=api-cert address=192.168.18.0/24
/ip service enable api-ssl
```

```bash
~/venv/ros/bin/python audit_ros.py --host 192.168.18.2 --port 8729 --ssl --user auditor --ask-pass
```

El script no verifica el certificado (RouterOS usa autofirmados): cifra, pero no
autentica el extremo.

## 4. Ejecución

### 4.1 Interactivo (recomendado)

```bash
rosaudit
```

```
  ┌────────────────────────────────────────────────┐
  │   Auditoría MikroTik  ·  modo interactivo      │
  └────────────────────────────────────────────────┘
  Enter para aceptar el valor entre corchetes.

  IP o host del router [192.168.18.2]:
  Usuario API (solo lectura) [auditor]:
  ¿API-SSL? [s/N]:
  Puerto API [8728]:
  Contraseña para auditor@192.168.18.2:
  Carpeta de informes [~/auditoria-mikrotik]:
  Formato (pdf / md / json / todos) [todos]:
```

Genera `informe-<host>-<AAAAMMDD-HHMM>.pdf` en la carpeta indicada y ofrece abrirlo.
Los valores se guardan en `~/.config/rosaudit/config.json` **salvo la contraseña**.

### 4.2 Con argumentos

```bash
rosaudit --host 127.0.0.1 --user auditor --ask-pass \
  --md informe.md --html informe.html --pdf informe.pdf --json informe.json
```

Opciones:

| Flag | Uso |
|---|---|
| `--ask-pass` | Pide la contraseña (recomendado; `--pass` queda en el historial) |
| `--md FICHERO` | Informe Markdown con tabla de hallazgos |
| `--html FICHERO` | Informe HTML con estilos, listo para imprimir |
| `--pdf FICHERO` | Informe PDF (convierte con `weasyprint` si está instalado) |
| `--json FICHERO` | Hallazgos en JSON, para automatizar o comparar |
| `--open` | Abre el PDF al terminar |
| `--ssl --port 8729` | API-SSL (requiere certificado asignado a `api-ssl`) |
| `--timeout SEG` | Timeout de conexión (15 s por defecto) |

Los ficheros se crean en la ruta que indiques (relativa al directorio desde el
que ejecutas). Si no pasas `--md/--html/--pdf/--json`, solo verás el resultado
por pantalla y **no se escribe ningún informe**.

## 5. Qué comprueba

Servicios de gestión expuestos, usuarios y privilegios, firewall IPv4/IPv6,
descubrimiento (MNDP/LLDP), RoMON, bandwidth-server, IP Cloud, proxy/SOCKS,
SNMP, propuestas y peers IPsec, peers WireGuard, túneles sin cifrar
(EoIP/GRE/IPIP/VPLS), servidores L2TP/PPTP/SSTP, OSPF/BGP sin autenticación,
syslog remoto, NTP, schedulers/scripts, VLAN filtering en bridges y reglas de
firewall duplicadas. Los hallazgos idénticos se fusionan y se muestran con `(xN)`.

## 6. Problemas típicos

| Síntoma | Causa / solución |
|---|---|
| `Login rechazado` | Usuario sin policy `api`, password mal, o `address=` no incluye tu IP |
| `Conexión rechazada` | `/ip service api` deshabilitado o `address=` no te incluye |
| `Timeout` | Firewall de entrada bloquea 8728, o el túnel SSH no está activo |
| `no se pudo leer /routing/...` | Normal en RouterOS 6: esa ruta es de v7. Se omite y sigue |
| `ssl` falla | `api-ssl` sin certificado instalado → usa el túnel SSH |

## 7. Límites

- Foto de la configuración: no sustituye captura de tráfico ni revisión de logs.
- No detecta contraseñas débiles (la API no las expone).
- En v6 se omiten los checks de OSPF/BGP/WireGuard (rutas v7).
- Usar únicamente contra equipos propios o con autorización por escrito.
