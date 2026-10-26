# RosAudit

**Auditoría de seguridad read-only para routers MikroTik (RouterOS 6.x / 7.x) vía API.**

Conecta con un usuario de solo lectura, ejecuta exclusivamente comandos `/print` (nunca modifica nada, no reinicia, no corta tráfico) y genera un informe de hallazgos en Markdown, HTML, PDF o JSON.

> ⚠️ Úsalo solo contra equipos propios o con autorización por escrito.

---

## Por qué existe

La mayoría de guías de hardening de MikroTik son checklists manuales. RosAudit las convierte en una comprobación automática y repetible: lánzalo antes y después de aplicar cambios, guarda el JSON y compara.

## Qué comprueba

- Servicios de gestión expuestos (telnet, ftp, www, api, winbox) y SSH sin `strong-crypto`
- Usuarios: cuenta `admin` activa, cuentas con privilegios totales (incluyendo grupos personalizados equivalentes a `full`)
- Firewall IPv4/IPv6: cadena `input` sin filtrar, sin drop final, reglas `accept` demasiado amplias, reglas duplicadas
- Descubrimiento de vecinos (MNDP/LLDP/CDP), RoMON, bandwidth-server, IP Cloud DDNS, proxy/SOCKS abiertos
- SNMP con comunidades por defecto (`public`/`private`) o sin cifrar (v2c)
- IPsec: propuestas con cifrado/hash débiles, modo `aggressive`, `generate-policy`
- WireGuard con `allowed-address` a ruta por defecto
- Túneles sin cifrar (EoIP/GRE/IPIP/VPLS), servidores L2TP/PPTP/SSTP
- OSPF/BGP sin autenticación
- Falta de syslog remoto o NTP
- Scripts y tareas programadas (vector de persistencia habitual en compromisos)
- Bridges sin `vlan-filtering`

Los hallazgos idénticos se fusionan y se muestran con un contador `(xN)`.

## Instalación

### Linux / macOS

```bash
python3 -m venv ~/venv/ros
~/venv/ros/bin/pip install librouteros

cp rosaudit ~/.local/bin/rosaudit
chmod +x ~/.local/bin/rosaudit
```

### Windows (PowerShell)

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install librouteros
```

> En Windows, dentro del entorno virtual usa siempre `python`, no `python3` — el venv de Windows no crea un ejecutable `python3.exe`, y `python3` puede acabar resolviendo al Python del sistema (sin `librouteros` instalado).

## Usuario de solo lectura en el router

```routeros
/user group add name=auditor policy=read,api
/user add name=auditor group=auditor password=<fuerte> address=<tu-ip>/32
/ip service enable api
```

`policy=read,api` es suficiente: `read` permite `/print` y `api` permite autenticarse por la API. No necesita `write`, `sensitive` ni `policy`.

## Uso

### Interactivo (recomendado)

```bash
rosaudit
```

Pregunta por pantalla host, usuario, contraseña, formato y carpeta de salida; al terminar ofrece abrir el PDF. Recuerda los últimos valores (nunca la contraseña) en `~/.config/rosaudit/config.json`.

### Con argumentos

```bash
# Linux/macOS
rosaudit --host 192.168.18.2 --user auditor --ask-pass --pdf informe.pdf

# Windows
python audit_ros.py --host 192.168.18.2 --user auditor --ask-pass --html informe.html
```

| Flag | Uso |
|---|---|
| `--ask-pass` | Pide la contraseña por pantalla (recomendado; `--pass` queda en el historial) |
| `--md FICHERO` | Informe Markdown con tabla de hallazgos |
| `--html FICHERO` | Informe HTML con estilos, listo para imprimir |
| `--pdf FICHERO` | Informe PDF (requiere `weasyprint`) |
| `--json FICHERO` | Hallazgos en JSON, para automatizar o comparar informes |
| `--open` | Abre el PDF al terminar |
| `--ssl --port 8729` | API-SSL (requiere certificado asignado a `api-ssl`; por defecto usa el puerto 8729 si pasas `--ssl` sin `--port`) |
| `--timeout SEG` | Timeout de conexión (15 s por defecto) |

### Conexión cifrada

La API en el puerto 8728 **no cifra**. Opciones si no estás en una VLAN de gestión aislada:

- **Túnel SSH**: `ssh -f -N -L 8728:127.0.0.1:8728 admin@<router>` y conecta contra `127.0.0.1`.
- **API-SSL**: certificado autofirmado asignado a `api-ssl`, conecta con `--ssl --port 8729`. El script no verifica el certificado (cifra, pero no autentica el extremo).

## Generar PDF

Requiere [`weasyprint`](https://weasyprint.org/). En Linux/macOS suele instalarse sin complicaciones (`pip install weasyprint`); en Windows depende de GTK y es más tedioso. Alternativa sencilla en cualquier plataforma: genera el `--html` y usa "Imprimir → Guardar como PDF" desde el navegador.

## Límites

- Es una foto de la configuración: no sustituye captura de tráfico ni revisión de logs.
- No detecta contraseñas débiles (la API no las expone).
- En RouterOS v6 se omiten los checks de OSPF/BGP/WireGuard (son rutas de v7).

## Hardening de referencia

Este repo incluye [`hardening-base.rsc`](./hardening-base.rsc), una plantilla de configuración base para RouterOS 7.x (servicios mínimos, firewall con anti fuerza bruta escalonado, logging remoto, política de contraseñas, etc.) pensada para aplicarse bloque a bloque y luego verificarse con RosAudit.

## Licencia

MIT (o la que prefieras añadir aquí).
