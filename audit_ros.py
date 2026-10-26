#!/usr/bin/env python3
"""
Auditoría READ-ONLY de un router MikroTik (RouterOS 6.x / 7.x) vía API.

No modifica nada: solo ejecuta comandos /print. Ejecútalo desde tu equipo
contra el router, con un usuario de solo lectura si es posible.

    python3 -m venv ~/venv/ros && ~/venv/ros/bin/pip install librouteros
    ~/venv/ros/bin/python audit_ros.py --host 10.0.0.1 --user auditor --ask-pass
    ~/venv/ros/bin/python audit_ros.py --host 10.0.0.1 --user auditor --ask-pass --md informe.md

Si usas API-SSL (8729):
    ... --ssl --port 8729

Autorización: úsalo únicamente contra equipos propios o con permiso escrito.
"""

import argparse
import getpass
import html as html_mod
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
from datetime import datetime

try:
    from librouteros import connect
except ImportError:  # se permite --help sin dependencias instaladas
    connect = None

SEV_ORDER = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
SEV_ICON = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵", "INFO": "⚪"}

findings = []
_seen = {}


def add(sev, check, detail, fix):
    """Añade un hallazgo, fusionando duplicados exactos y contando repeticiones."""
    key = (sev, check, detail)
    prev = _seen.get(key)
    if prev is not None:
        prev["count"] += 1
        return
    item = {"sev": sev, "check": check, "detail": detail, "fix": fix, "count": 1}
    _seen[key] = item
    findings.append(item)


def isp(v):
    """RouterOS devuelve 'true'/'false' como texto; las propiedades falsas a veces se omiten."""
    return str(v).lower() in ("true", "yes", "1")


def has(v, *needles):
    s = str(v).lower()
    return any(n in s for n in needles)


class Ros:
    def __init__(self, api):
        self.api = api

    def q(self, path):
        try:
            return list(self.api(path))
        except Exception as e:  # noqa: BLE001 - un path ausente no debe romper la auditoría
            print(f"  ! no se pudo leer {path}: {e}", file=sys.stderr)
            return []

    def one(self, path):
        rows = self.q(path)
        return rows[0] if rows else {}


def audit(ros):
    findings.clear()
    _seen.clear()
    # ---------- plataforma ----------
    res = ros.one("/system/resource/print")
    ver = res.get("version", "?")
    add("INFO", "Versión RouterOS", f"{ver} | board={res.get('board-name','?')} | uptime={res.get('uptime','?')}",
        "Contrastar con los avisos de seguridad de MikroTik y actualizar si hay CVE que aplique.")
    m = re.match(r"^(\d+)\.(\d+)", ver)
    if m and int(m.group(1)) < 7:
        add("ALTO", "RouterOS v6 (fin de soporte)",
            f"Versión {ver}: la rama 6.x ya no recibe parches de seguridad.",
            "Migrar a v7 si el hardware lo permite, o aislar el equipo al mínimo imprescindible.")

    # ---------- servicios de gestión ----------
    svc = ros.q("/ip/service/print")
    risky = {"telnet": "CRITICO", "ftp": "CRITICO", "www": "MEDIO", "api": "MEDIO",
             "winbox": "ALTO", "api-ssl": "BAJO", "ssh": "BAJO", "www-ssl": "BAJO"}
    for s in svc:
        name = s.get("name", "")
        if isp(s.get("disabled")):
            continue
        addr = s.get("address", "")
        exposed = not addr or addr.strip() in ("0.0.0.0/0", "::/0")
        if name in ("telnet", "ftp") and exposed:
            add("CRITICO", f"Servicio {name} expuesto",
                f"{name} habilitado y sin restricción de origen (address={addr or 'todas'}). Tráfico en claro.",
                f"/ip service disable {name}  (usar SSH en su lugar)")
        elif name == "winbox" and exposed:
            add("ALTO", "Winbox accesible sin filtro de origen",
                f"Winbox/8291 abierto a cualquier origen (address={addr or 'todas'}).",
                "Restringir: /ip service set winbox address=<red de gestión> y filtrar 8291 en input.")
        elif name in ("www", "api") and exposed:
            add("MEDIO", f"Servicio {name} expuesto",
                f"{name} habilitado sin address= (address={addr or 'todas'}).",
                f"Deshabilitar si no se usa, o limitar por address= y firewall input.")
        elif name == "ssh":
            ssh = ros.one("/ip/ssh/print")
            if not isp(ssh.get("strong-crypto", "false")):
                add("ALTO", "SSH sin strong-crypto",
                    "Permite algoritmos/KEX débiles en el servicio SSH.",
                    "/ip ssh set strong-crypto=yes")

    # ---------- usuarios ----------
    users = ros.q("/user/print")
    groups = {g.get("name"): g.get("policy", "") for g in ros.q("/user/group/print")}
    for u in users:
        if isp(u.get("disabled")):
            continue
        name = u.get("name", "")
        grp = u.get("group", "")
        policy = groups.get(grp, "")
        if name == "admin":
            add("MEDIO", "Usuario 'admin' activo",
                "Nombre por defecto, objetivo preferente de fuerza bruta.",
                "Crear usuario propio con grupo full y deshabilitar/renombrar 'admin'.")
        # 'full' es el grupo integrado, pero un grupo personalizado con policy
        # equivalente (write+policy+sensitive) da el mismo control total.
        full_equiv = grp == "full" or all(p in policy for p in ("write", "policy", "sensitive"))
        if full_equiv and name != "admin":
            add("INFO", f"Usuario con privilegios totales: {name}",
                f"Grupo '{grp}' con policy equivalente a 'full' ({policy or '?'}).",
                "Aplicar mínimo privilegio con grupos personalizados.")
    if len(users) > 5:
        add("INFO", "Inventario de usuarios",
            f"{len(users)} usuarios definidos; revisar cuentas huérfanas o de terceros.",
            "Depurar y documentar cada cuenta.")

    # ---------- firewall IPv4 / IPv6 ----------
    fw = [r for r in ros.q("/ip/firewall/filter/print") if not isp(r.get("disabled"))]
    input_rules = [r for r in fw if r.get("chain") == "input"]
    catch_all_drop = [r for r in input_rules
                      if r.get("action") == "drop"
                      and not r.get("src-address") and not r.get("in-interface")
                      and not r.get("in-interface-list")]
    if not input_rules:
        add("CRITICO", "Sin reglas en cadena input",
            "El router no filtra tráfico dirigido a él mismo.",
            "Aplicar política por defecto drop en input (ver guía de hardening de MikroTik).")
    elif not catch_all_drop:
        add("ALTO", "Input sin drop final",
            "No hay una regla drop incondicional al final de la cadena input.",
            "Añadir al final de input: action=drop (tras accept established/related y servicios de gestión).")

    for r in input_rules:
        if r.get("action") != "accept" or isp(r.get("disabled")):
            continue
        # accept established/related/untracked e ICMP con limit= son reglas
        # estándar de cualquier firewall bien hecho (incluido hardening-base.rsc):
        # no tiene sentido exigirles src-address/in-interface, serían falsos positivos.
        cs = str(r.get("connection-state", "")).lower()
        if any(s in cs for s in ("established", "related", "untracked")):
            continue
        if str(r.get("protocol", "")).lower() == "icmp" and r.get("limit"):
            continue
        broad = not r.get("src-address") and not r.get("in-interface") and not r.get("in-interface-list")
        port = r.get("dst-port", "")
        if broad and port:
            add("ALTO", f"Accept amplio en input (puerto {port})",
                f"Regla acepta {port} desde cualquier origen sin restricción de interfaz/lista.",
                "Limitar con src-address y/o in-interface-list=MGMT.")
        elif broad:
            add("MEDIO", "Accept amplio en input",
                f"Regla accept sin src-address ni in-interface: {r.get('comment','(sin comentario)')}",
                "Restringir origen; revisar si es necesaria.")

    fw6 = [r for r in ros.q("/ipv6/firewall/filter/print") if not isp(r.get("disabled"))]
    if not fw6:
        add("ALTO", "Sin firewall IPv6",
            "Si hay direccionamiento IPv6, el router queda sin filtrar por esa vía.",
            "Crear reglas equivalentes en /ipv6/firewall/filter (input/forward).")

    # reglas idénticas repetidas: comparación EXACTA (todos los campos), no una lista parcial
    rt_keys = {".id", "bytes", "packets", "dynamic", "invalid", "inactive"}

    def rule_sig(r):
        return tuple(sorted((k, str(v)) for k, v in r.items() if k not in rt_keys))

    rule_groups = {}
    for r in ros.q("/ip/firewall/filter/print"):
        rule_groups.setdefault(rule_sig(r), []).append(r)

    dups = {sig: rows for sig, rows in rule_groups.items() if len(rows) > 1}
    if dups:
        ejemplos = []
        for sig, rows in list(dups.items())[:3]:
            d = dict(sig)
            partes = [d.get("chain", "?"), d.get("action", "?")]
            for k in ("protocol", "dst-port", "src-address-list", "dst-address-list",
                      "src-address", "dst-address", "in-interface", "comment"):
                if d.get(k):
                    partes.append(f"{k}={d[k]}")
            ejemplos.append(f"{' / '.join(partes[:2])} [{' '.join(partes[2:])}] x{len(rows)}")
        add("BAJO", "Reglas de firewall duplicadas",
            f"{sum(len(v) for v in dups.values())} reglas en {len(dups)} grupo(s): "
            + "; ".join(ejemplos),
            "Verifica con /ip firewall filter print; si no aparecen, avisa: sería un falso positivo.")

    # ---------- descubrimiento y servicios auxiliares ----------
    disc = ros.q("/ip/neighbor/discovery-settings/print")
    protos = ",".join(str(d.get("protocol", "")) for d in disc)
    if "mndp" in protos or "lldp" in protos or "cdp" in protos:
        lists = ",".join(str(d.get("discover-interface-list", "")) for d in disc)
        sev = "MEDIO" if "all" in lists.lower() or not lists else "BAJO"
        add(sev, "Descubrimiento de vecinos activo",
            f"Protocolos: {protos or 'mndp'} | interface-list: {lists or 'todas'}. Revela modelo/versión a cualquiera en el segmento.",
            "/ip neighbor discovery-settings set discover-interface-list=<interno> (nunca la WAN).")

    romon = ros.one("/tool/romon/print")
    if isp(romon.get("enabled")):
        add("ALTO", "RoMON habilitado",
            "RoMON permite gestión entre equipos sin IP; un vecino malicioso puede alcanzar el router.",
            "/tool romon set enabled=no (o restringir interfaces).")

    bw = ros.one("/tool/bandwidth-server/print")
    if isp(bw.get("enabled")):
        add("MEDIO", "Bandwidth-server habilitado",
            f"autenticación={bw.get('authenticate','?')}. Usado en amplificación/abuso de ancho de banda.",
            "/tool bandwidth-server set enabled=no")

    cloud = ros.one("/ip/cloud/print")
    if isp(cloud.get("ddns-enabled")):
        add("MEDIO", "IP Cloud DDNS activo",
            f"DNS público: {cloud.get('dns-name','?')} — publica la IP del router.",
            "/ip cloud set ddns-enabled=no si no se usa.")

    if isp(ros.one("/ip/proxy/print").get("enabled")):
        add("ALTO", "Proxy HTTP habilitado", "Puede usarse como proxy abierto.",
            "/ip proxy set enabled=no")
    if isp(ros.one("/ip/socks/print").get("enabled")):
        add("ALTO", "SOCKS habilitado", "Puede usarse como relay abierto.",
            "/ip socks set enabled=no")

    snmp = ros.q("/snmp/community/print")
    for c in snmp:
        cname = c.get("name", "")
        if isp(c.get("disabled")):
            continue
        sev = "ALTO" if cname in ("public", "private") else "MEDIO"
        add(sev, f"SNMP community '{cname}'",
            f"address={c.get('address','todas')} — v2c no cifra ni autentica.",
            "Migrar a SNMPv3 (auth+priv) y limitar por address/firewall.")

    # ---------- IPsec ----------
    for p in ros.q("/ip/ipsec/proposal/print"):
        name = p.get("name", "?")
        enc, auth, pfs = p.get("enc-algorithms", ""), p.get("auth-algorithms", ""), p.get("pfs-group", "")
        weak = has(enc, "3des", "des", "null") or has(auth, "md5", "sha1") or has(pfs, "modp1024", "modp768")
        if weak:
            add("ALTO", f"Propuesta IPsec débil: {name}",
                f"enc={enc} auth={auth} pfs={pfs}",
                "Usar aes-256-gcm/aes-256-cbc + sha256+ y DH ecp256/modp2048+, PFS activo.")
    for peer in ros.q("/ip/ipsec/peer/print"):
        if isp(peer.get("disabled")):
            continue
        if isp(peer.get("generate-policy")):
            add("MEDIO", f"IPsec peer con generate-policy: {peer.get('address','?')}",
                "Crea políticas dinámicas difíciles de auditar.",
                "/ip ipsec peer set <peer> generate-policy=no")
        if has(peer.get("exchange-mode", ""), "aggressive"):
            add("ALTO", "IKE en modo aggressive",
                f"Peer {peer.get('address','?')}: el modo aggressive filtra identidad y facilita crackeo de PSK.",
                "Usar IKEv2 (exchange-mode=ike2) con certificados.")

    # ---------- WireGuard ----------
    for wg in ros.q("/interface/wireguard/peers/print"):
        allow = wg.get("allowed-address", "")
        if "0.0.0.0/0" in allow or "::/0" in allow:
            add("MEDIO", "WireGuard peer con ruta por defecto",
                f"Peer {wg.get('interface','?')} allowed-address={allow}",
                "Limitar allowed-address a la subred concreta del peer.")

    # ---------- túneles sin cifrar ----------
    plain = []
    for i in ros.q("/interface/print"):
        t = str(i.get("type", "")).lower()
        if t in ("eoip", "gre", "gre6", "ipip", "vpls") and not isp(i.get("disabled")):
            plain.append(f"{i.get('name')}({t})")
    if plain:
        add("ALTO", "Túneles de capa 2/3 sin cifrado",
            "Detectados: " + ", ".join(plain) + ". EoIP/GRE/IPIP/VPLS no cifran por sí mismos.",
            "Encapsular dentro de IPsec o migrar a WireGuard.")

    # ---------- servidores de acceso remoto ----------
    for path, label in (("/interface/l2tp-server/server/print", "L2TP"),
                        ("/interface/pptp-server/server/print", "PPTP"),
                        ("/interface/sstp-server/server/print", "SSTP")):
        srv = ros.one(path)
        if isp(srv.get("enabled")):
            sev = "ALTO" if label == "PPTP" else "MEDIO"
            add(sev, f"Servidor {label} habilitado",
                f"Perfiles/usuarios de acceso remoto activos ({label}).",
                "Revisar usuarios, exigir IPsec/certificados y deshabilitar PPTP (obsoleto e inseguro).")

    # ---------- routing dinámico ----------
    for o in ros.q("/routing/ospf/interface-template/print"):
        if not o.get("authentication"):
            add("MEDIO", "OSPF sin autenticación",
                f"Área/interfaz {o.get('area','?')} sin authentication.",
                "Activar authentication=md5/sha1 con clave por vecino.")
    for b in ros.q("/routing/bgp/connection/print"):
        if isp(b.get("disabled")):
            continue
        if not b.get("tcp-md5-key"):
            add("BAJO", f"BGP sin TCP-MD5: {b.get('name','?')}",
                "Sesión BGP sin autenticación de transporte.",
                "Configurar tcp-md5-key y filtros de prefijos en ambos extremos.")

    # ---------- logging / NTP ----------
    remote = [a for a in ros.q("/system/logging/action/print")
              if a.get("target") == "remote" and not isp(a.get("disabled"))]
    if not remote:
        add("MEDIO", "Sin syslog remoto",
            "Los logs solo viven en memoria del router; se pierden al reiniciar y no hay correlación.",
            "/system logging action add name=remote target=remote remote=<ip> remote-port=514")
    if not isp(ros.one("/system/ntp/client/print").get("enabled")):
        add("BAJO", "NTP cliente deshabilitado",
            "Sin hora fiable, los logs y la validez de certificados/IPsec fallan.",
            "/system ntp client set enabled=yes servers=<ntp interno>")

    # ---------- persistencia ----------
    sched = [s for s in ros.q("/system/scheduler/print") if not isp(s.get("disabled"))]
    scripts = ros.q("/system/script/print")
    if sched:
        add("INFO", "Tareas programadas",
            f"{len(sched)} scheduler activos: " + ", ".join(s.get("name", "?") for s in sched),
            "Revisar que cada tarea sea legítima y documentada (vector de persistencia).")
    if scripts:
        add("INFO", "Scripts definidos",
            f"{len(scripts)} scripts: " + ", ".join(s.get("name", "?") for s in scripts),
            "Auditar contenido; scripts no documentados = posible puerta trasera.")

    # ---------- L2 ----------
    for br in ros.q("/interface/bridge/print"):
        if not isp(br.get("vlan-filtering")):
            add("BAJO", f"Bridge sin vlan-filtering: {br.get('name','?')}",
                "Segmentación L2 dependiente de configuración manual de puertos.",
                "/interface bridge set <bridge> vlan-filtering=yes (con planificación).")


def render_md(host, rows):
    out = [f"# Auditoría MikroTik — {host}", "", f"Fecha: {datetime.now():%Y-%m-%d %H:%M}", ""]
    counts = {}
    for r in rows:
        counts[r["sev"]] = counts.get(r["sev"], 0) + 1
    out.append("## Resumen")
    out.append("")
    for s in SEV_ORDER:
        if counts.get(s):
            out.append(f"- {SEV_ICON[s]} **{s}**: {counts[s]}")
    out += ["", "## Hallazgos", "", "| Sev | Comprobación | Detalle | Remediación |", "|---|---|---|---|"]
    for r in rows:
        clean = lambda x: str(x).replace("|", "\\|").replace("\n", " ")
        rep = f" (x{r['count']})" if r.get("count", 1) > 1 else ""
        out.append(f"| {SEV_ICON[r['sev']]} {r['sev']} | {clean(r['check'])}{rep} | {clean(r['detail'])} | `{clean(r['fix'])}` |")
    return "\n".join(out)


SEV_COLOR = {"CRITICO": "#b00020", "ALTO": "#d9480f", "MEDIO": "#b8860b",
             "BAJO": "#1c7ed6", "INFO": "#6c757d"}


def render_html(host, rows):
    e = html_mod.escape
    counts = {}
    for r in rows:
        counts[r["sev"]] = counts.get(r["sev"], 0) + 1

    cards = "".join(
        f'<div class="card"><span class="num" style="color:{SEV_COLOR[s]}">{counts[s]}</span>'
        f'<span class="lbl">{s}</span></div>'
        for s in SEV_ORDER if counts.get(s)
    )

    body = []
    for r in rows:
        c = SEV_COLOR[r["sev"]]
        rep = f' <span class="rep">(x{r["count"]})</span>' if r.get("count", 1) > 1 else ""
        body.append(
            f'<tr><td><span class="badge" style="background:{c}">{r["sev"]}</span></td>'
            f'<td><strong>{e(r["check"])}</strong>{rep}<br><span class="detail">{e(r["detail"])}</span></td>'
            f'<td><code>{e(r["fix"])}</code></td></tr>'
        )

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Auditoría MikroTik — {e(host)}</title>
<style>
  @page {{ size: A4; margin: 18mm 14mm; }}
  body {{ font-family: "DejaVu Sans", Arial, sans-serif; color:#1a1a1a; font-size:10.5pt; }}
  h1 {{ font-size:19pt; margin:0 0 2mm; }}
  .meta {{ color:#666; font-size:9pt; margin-bottom:8mm; }}
  .cards {{ margin:6mm 0 10mm; }}
  .card {{ display:inline-block; border:1px solid #ddd; border-radius:6px;
           padding:4mm 6mm; text-align:center; min-width:22mm; margin:0 4mm 4mm 0; }}
  .num {{ display:block; font-size:20pt; font-weight:bold; line-height:1; }}
  .lbl {{ font-size:8pt; color:#555; letter-spacing:.5px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; font-size:8.5pt; text-transform:uppercase; color:#555;
        border-bottom:2px solid #333; padding:2mm 2mm; }}
  td {{ border-bottom:1px solid #e5e5e5; padding:3mm 2mm; vertical-align:top; }}
  .badge {{ color:#fff; font-size:7.5pt; font-weight:bold; padding:1mm 2mm; border-radius:3px; }}
  .detail {{ color:#444; font-size:9pt; }}
  .rep {{ color:#888; font-size:8.5pt; }}
  code {{ font-family:"DejaVu Sans Mono", monospace; font-size:8pt; color:#0b5394;
          background:#f4f6f8; padding:1mm 1.5mm; border-radius:3px; display:inline-block; }}
  tr {{ page-break-inside: avoid; }}
</style></head><body>
<h1>Auditoría de configuración MikroTik</h1>
<div class="meta">Equipo: <strong>{e(host)}</strong> &nbsp;·&nbsp; Fecha: {datetime.now():%Y-%m-%d %H:%M}
&nbsp;·&nbsp; Modo: solo lectura (API /print)</div>
<div class="cards">{cards}</div>
<table><thead><tr><th style="width:22mm">Severidad</th><th>Hallazgo</th><th style="width:62mm">Remediación</th></tr></thead>
<tbody>{''.join(body)}</tbody></table>
</body></html>"""


def make_ssl_wrapper(host):
    """RouterOS usa certificados autofirmados: no verificamos cadena ni hostname."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def wrap(sock):
        return ctx.wrap_socket(sock, server_hostname=host)

    return wrap


CONFIG_PATH = os.path.expanduser("~/.config/rosaudit/config.json")


def load_config():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def ask(label, default=""):
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {label}{suffix}: ").strip()
    except EOFError:
        return default
    return val or default


def ask_yes(label, default=False):
    opts = "S/n" if default else "s/N"
    try:
        val = input(f"  {label} [{opts}]: ").strip().lower()
    except EOFError:
        return default
    if not val:
        return default
    return val in ("s", "si", "sí", "y", "yes")


def ask_port(default):
    while True:
        raw = ask("Puerto API", str(default))
        try:
            return int(raw)
        except ValueError:
            print("  ! puerto inválido, escribe un número")


def wizard(a):
    cfg = load_config()
    last = cfg.get("last", {})
    print()
    print("  ┌────────────────────────────────────────────────┐")
    print("  │   Auditoría MikroTik  ·  modo interactivo      │")
    print("  └────────────────────────────────────────────────┘")
    print("  Enter para aceptar el valor entre corchetes.\n")

    a.host = ask("IP o host del router", last.get("host", "192.168.18.2"))
    a.user = ask("Usuario API (solo lectura)", last.get("user", "auditor"))
    a.ssl = ask_yes("¿API-SSL?", last.get("ssl", False))
    a.port = ask_port(last.get("port", 8729 if a.ssl else 8728))
    try:
        a.password = getpass.getpass(f"  Contraseña para {a.user}@{a.host}: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelado.")
        sys.exit(130)

    outdir = os.path.expanduser(
        ask("Carpeta de informes", last.get("outdir", "~/auditoria-mikrotik")))
    fmt = ask("Formato (pdf / md / json / todos)", last.get("fmt", "todos")).lower()
    if fmt not in ("pdf", "md", "json", "todos"):
        print("  ! formato no reconocido, uso 'todos'")
        fmt = "todos"

    os.makedirs(outdir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", a.host)
    base = os.path.join(outdir, f"informe-{safe}-{datetime.now():%Y%m%d-%H%M}")
    if fmt in ("pdf", "todos"):
        a.pdf = base + ".pdf"
        a.html = base + ".html"
    if fmt in ("md", "todos"):
        a.md = base + ".md"
    if fmt in ("json", "todos"):
        a.json = base + ".json"

    save_config({"last": {"host": a.host, "user": a.user, "ssl": a.ssl,
                          "port": a.port, "outdir": outdir, "fmt": fmt}})
    print()


def build_parser():
    ap = argparse.ArgumentParser(
        description="Auditoría de configuración MikroTik (solo lectura). "
                    "Sin --host entra en modo interactivo.")
    ap.add_argument("--host", help="IP del router (si se omite, pregunta por pantalla)")
    ap.add_argument("--user", help="Usuario API")
    ap.add_argument("--pass", dest="password", default=None)
    ap.add_argument("--ask-pass", action="store_true", help="Pedir la contraseña por pantalla")
    ap.add_argument("--port", type=int, default=None,
                    help="Puerto API (por defecto 8728, u 8729 si se usa --ssl)")
    ap.add_argument("--ssl", action="store_true")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--md", help="Informe Markdown")
    ap.add_argument("--html", help="Informe HTML")
    ap.add_argument("--pdf", help="Informe PDF (weasyprint)")
    ap.add_argument("--json", help="Hallazgos en JSON")
    ap.add_argument("--open", action="store_true", help="Abrir el PDF al terminar")
    return ap


def main():
    ap = build_parser()
    a = ap.parse_args()

    if connect is None:
        sys.exit("Falta librouteros:  python3 -m venv ~/venv/ros && "
                 "~/venv/ros/bin/pip install librouteros")

    interactive = not a.host
    if interactive:
        if not sys.stdin.isatty():
            ap.error("falta --host (y no hay terminal para el modo interactivo)")
        wizard(a)
    elif not a.user:
        ap.error("--user es obligatorio cuando se usa --host")

    if a.port is None:
        a.port = 8729 if a.ssl else 8728

    password = a.password
    if password is None and a.ask_pass:
        password = getpass.getpass(f"Password para {a.user}@{a.host}: ")

    print(f"[*] Conectando a {a.host}:{a.port} (ssl={a.ssl}) como {a.user}")
    kwargs = dict(host=a.host, username=a.user, password=password,
                  port=a.port, timeout=a.timeout)
    if a.ssl:
        kwargs["ssl_wrapper"] = make_ssl_wrapper(a.host)
    try:
        api = connect(**kwargs)
    except Exception as e:  # noqa: BLE001
        msg = str(e).lower()
        if "password" in msg or "login" in msg or "trap" in msg:
            sys.exit("[-] Login rechazado: revisa usuario/contraseña y que el grupo tenga policy 'api'.")
        if "refused" in msg:
            sys.exit(f"[-] Conexión rechazada en {a.host}:{a.port}. ¿Está habilitado /ip service api?")
        if "timed out" in msg or "timeout" in msg:
            sys.exit(f"[-] Timeout hacia {a.host}:{a.port}. Firewall, ruta o servicio caído.")
        sys.exit(f"[-] Error de conexión: {e}")

    ros = Ros(api)
    print("[*] Ejecutando comprobaciones read-only...")
    audit(ros)
    api.close()

    findings.sort(key=lambda r: SEV_ORDER[r["sev"]])
    print()
    for r in findings:
        rep = f"  (x{r['count']})" if r.get("count", 1) > 1 else ""
        print(f"{SEV_ICON[r['sev']]} [{r['sev']}] {r['check']}{rep}")
        print(f"    {r['detail']}")
        print(f"    -> {r['fix']}")

    counts = {}
    for r in findings:
        counts[r["sev"]] = counts.get(r["sev"], 0) + 1
    resumen = " · ".join(f"{counts[s]} {s}" for s in SEV_ORDER if counts.get(s))
    print(f"\n[*] Resumen: {resumen or 'sin hallazgos'}")

    if a.md:
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(render_md(a.host, findings))
        print(f"[+] Informe Markdown: {os.path.abspath(a.md)}")

    pdf_ok = False
    if a.html or a.pdf:
        html_path = a.html or (os.path.splitext(a.pdf)[0] + ".html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(render_html(a.host, findings))
        print(f"[+] Informe HTML: {os.path.abspath(html_path)}")

        if a.pdf:
            exe = shutil.which("weasyprint")
            if exe:
                subprocess.run([exe, os.path.abspath(html_path), os.path.abspath(a.pdf)],
                               check=False)
                if os.path.exists(a.pdf):
                    pdf_ok = True
                    print(f"[+] Informe PDF: {os.path.abspath(a.pdf)}")
                else:
                    print("[-] weasyprint falló; abre el HTML y usa 'Imprimir > Guardar como PDF'.")
            else:
                print("[-] weasyprint no instalado. Abre el HTML y usa 'Imprimir > Guardar como PDF'.")

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"host": a.host, "date": datetime.now().isoformat(), "findings": findings},
                      f, ensure_ascii=False, indent=2)
        print(f"[+] JSON: {os.path.abspath(a.json)}")

    if pdf_ok and a.pdf:
        abrir = a.open or (interactive and ask_yes("\n¿Abrir el PDF ahora?", True))
        if abrir:
            opener = shutil.which("xdg-open")
            if opener:
                subprocess.Popen([opener, os.path.abspath(a.pdf)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print(f"Abre manualmente: {os.path.abspath(a.pdf)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelado.")
        sys.exit(130)
