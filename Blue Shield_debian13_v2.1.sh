#!/usr/bin/env bash
# =============================================================================
# Fort-Blue Shield — Hardening Completo e Interactivo  ·  v2.1
# -----------------------------------------------------------------------------
# Cambios respecto a v2.0:
#   · PASO 11 (AppArmor) ampliado: instala apparmor-profiles(-extra), verifica
#     que AppArmor es un LSM activo, valida y despliega perfiles extra para los
#     binarios realmente instalados, y permite promover a enforce de forma
#     controlada. Antes solo contaba perfiles.
#   · PASO 12 NUEVO: auditd con reglas adaptadas a escritorio (dos niveles) y
#     auditd.conf sin acciones destructivas (nunca HALT/SINGLE).
#   · fortknox-clamscan.service endurecido con directivas systemd coherentes
#     con el modo de cuarentena, y verificado con 'systemd-analyze security'.
#   · PASO 15 NUEVO (opcional): sandboxing de aplicaciones — bubblewrap con el
#     envoltorio 'fortknox-sandbox', Flatpak + Flathub + Flatseal y un script
#     de recorte de permisos Flatpak que NO se aplica solo.
#   · CLAMAV_QUARANTINE: en escritorio el escaneo semanal es solo informe por
#     defecto (mover ficheros de /home por un falso positivo hace más daño que
#     bien). KERNEL_SYSRQ pasa a ser una decisión explícita.
#   · Exclusiones de AIDE ampliadas (/var/log/audit, /var/lib/flatpak, …).
#
# Cambios de v2.0 respecto a v1 (se mantienen):
#   · 4 bugs que abortaban la ejecución, perfiles workstation|server, sshd por
#     drop-in, 2FA funcional, nftables compatible con Docker, sysctl con IPv6.
#
# Seguro, idempotente, con backups automáticos. Ejecutar como root.
# =============================================================================

set -euo pipefail

export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"

# ─────────────────────────────────────────────────────────────
# CONFIGURACIÓN (sobreescribible con variables de entorno)
# ─────────────────────────────────────────────────────────────
PROFILE="${PROFILE:-workstation}"      # workstation | server

ENABLE_SSH="${ENABLE_SSH:-auto}"       # 1 | 0 | auto (server=1, workstation=0)
SSH_PORT="${SSH_PORT:-2222}"
ALLOW_SSH_CIDRS="${ALLOW_SSH_CIDRS:-}" # "192.168.1.0/24,fd00::/8"
ALLOW_SSH_PORT_22="${ALLOW_SSH_PORT_22:-0}"
ALLOW_TCP_FORWARDING="${ALLOW_TCP_FORWARDING:-auto}"  # yes | no | local | auto
PUBKEY="${PUBKEY:-}"
ENABLE_SSH_2FA="${ENABLE_SSH_2FA:-0}"

ALLOW_HTTP="${ALLOW_HTTP:-0}"
ALLOW_HTTPS="${ALLOW_HTTPS:-0}"
EXTRA_TCP_PORTS="${EXTRA_TCP_PORTS:-}" # "8006,9000"
EXTRA_UDP_PORTS="${EXTRA_UDP_PORTS:-}"

DOCKER_COMPAT="${DOCKER_COMPAT:-auto}" # 1 | 0 | auto
RP_FILTER="${RP_FILTER:-auto}"         # 1 (estricto) | 2 (laxo) | auto
PTRACE_SCOPE="${PTRACE_SCOPE:-1}"      # 0..3
KERNEL_SYSRQ="${KERNEL_SYSRQ:-auto}"   # 0 (desactivado) | 4 (solo consola) | 1 | auto

# ── AppArmor (v2.1) ──
APPARMOR_EXTRA_PROFILES="${APPARMOR_EXTRA_PROFILES:-auto}" # 1 | 0 | auto (workstation=1)
APPARMOR_EXTRA_MODE="${APPARMOR_EXTRA_MODE:-complain}"     # complain | enforce
APPARMOR_ENFORCE_ALL="${APPARMOR_ENFORCE_ALL:-0}"          # promueve TODO complain → enforce

# ── auditd (v2.1) ──
ENABLE_AUDITD="${ENABLE_AUDITD:-1}"
AUDIT_LEVEL="${AUDIT_LEVEL:-basic}"    # basic | strict (strict = mucho más ruido)
AUDIT_IMMUTABLE="${AUDIT_IMMUTABLE:-0}" # 1 = '-e 2' (requiere reinicio para cambiar reglas)

# ── Sandboxing de aplicaciones (v2.1) ──
ENABLE_SANDBOX="${ENABLE_SANDBOX:-auto}"     # 1 | 0 | auto (workstation=1)
INSTALL_FLATPAK="${INSTALL_FLATPAK:-auto}"   # 1 | 0 | auto (con ENABLE_SANDBOX y entorno gráfico)
INSTALL_FLATSEAL="${INSTALL_FLATSEAL:-1}"    # descarga el runtime de GNOME (~700 MB la 1ª vez)
FLATPAK_LOCKDOWN="${FLATPAK_LOCKDOWN:-0}"    # 1 = aplica el recorte global de permisos
ENABLE_FIREJAIL="${ENABLE_FIREJAIL:-0}"      # opt-in: ver advertencia en el PASO 15

ENABLE_CLAMAV="${ENABLE_CLAMAV:-1}"
CLAMAV_QUARANTINE="${CLAMAV_QUARANTINE:-auto}" # 1 | 0 | auto (workstation=0, server=1)
ENABLE_AIDE="${ENABLE_AIDE:-1}"
ASSUME_YES="${ASSUME_YES:-0}"

# ─────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────
STEP=0
LOGFILE=""

step() {
  STEP=$((STEP + 1))
  printf "\n\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
  printf "\033[1;34m[PASO %02d] %s\033[0m\n" "$STEP" "$*"
  printf "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
}

ok()   { printf "\033[1;32m  ✔ %s\033[0m\n" "$*"; }
info() { printf "\033[0;36m  ➜ %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m  ⚠ %s\033[0m\n" "$*"; }
err()  { printf "\033[1;31m  ✗ %s\033[0m\n" "$*"; }

result_block() { printf "\033[0;90m"; printf '%s\n' "$1" | sed 's/^/    | /'; printf "\033[0m"; }

pause_for_read() {
  [[ "$ASSUME_YES" == "1" ]] && return 0
  printf "\n\033[0;33m  [Presiona ENTER para continuar...]\033[0m"
  read -r _
}

# Ejecuta un comando registrando la salida completa en el log y mostrando resumen
run_logged() {
  local desc="$1"; shift
  info "$desc"
  if "$@" >>"$LOGFILE" 2>&1; then
    ok "$desc — OK"
  else
    local rc=$?
    err "$desc — FALLÓ (código $rc). Últimas líneas del log:"
    result_block "$(tail -15 "$LOGFILE")"
    return "$rc"
  fi
}

# ¿Existe el paquete en los repositorios configurados?
pkg_exists() { apt-cache show "$1" >/dev/null 2>&1; }

# Fija clave=valor en un fichero de configuración estilo 'clave = valor'
set_conf_key() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || return 0
  if grep -qE "^\s*#?\s*${key}\s*=" "$file"; then
    sed -i -E "s|^\s*#?\s*(${key})\s*=.*|\1 = ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >> "$file"
  fi
}

# ─────────────────────────────────────────────────────────────
# COMPROBACIONES PREVIAS
# ─────────────────────────────────────────────────────────────
require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Este script debe ejecutarse como root."
    exit 1
  fi
}

require_root

if ! command -v apt-get >/dev/null 2>&1; then
  err "Este script requiere un sistema basado en Debian con apt."
  exit 1
fi

if [[ "$PROFILE" != "workstation" && "$PROFILE" != "server" ]]; then
  err "PROFILE debe ser 'workstation' o 'server' (recibido: $PROFILE)."
  exit 1
fi

if [[ "$AUDIT_LEVEL" != "basic" && "$AUDIT_LEVEL" != "strict" ]]; then
  err "AUDIT_LEVEL debe ser 'basic' o 'strict' (recibido: $AUDIT_LEVEL)."
  exit 1
fi

if [[ "$APPARMOR_EXTRA_MODE" != "complain" && "$APPARMOR_EXTRA_MODE" != "enforce" ]]; then
  err "APPARMOR_EXTRA_MODE debe ser 'complain' o 'enforce'."
  exit 1
fi

BACKUP_DIR="/root/fortknox-backups/$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"
LOGFILE="$BACKUP_DIR/fortknox.log"
: > "$LOGFILE"

trap 'rc=$?; [[ $rc -ne 0 ]] && err "Fallo en la línea $LINENO (código $rc). Log: $LOGFILE"' ERR

# ─────────────────────────────────────────────────────────────
# RESOLUCIÓN DE VALORES 'auto'
# ─────────────────────────────────────────────────────────────

ADMIN_USER="${ADMIN_USER:-${SUDO_USER:-}}"
if [[ -z "$ADMIN_USER" ]]; then
  ADMIN_USER=$(awk -F: '$3>=1000 && $3<65534 {print $1; exit}' /etc/passwd || true)
fi
if [[ -z "$ADMIN_USER" ]] || ! id "$ADMIN_USER" >/dev/null 2>&1; then
  err "No se pudo determinar un usuario administrador válido."
  err "Defínelo explícitamente:  ADMIN_USER=tuusuario $0"
  exit 1
fi

if [[ "$ENABLE_SSH" == "auto" ]]; then
  [[ "$PROFILE" == "server" ]] && ENABLE_SSH=1 || ENABLE_SSH=0
fi

if [[ "$ALLOW_TCP_FORWARDING" == "auto" ]]; then
  # 'local' permite túneles -L (acceso a interfaces web del homelab) sin -R
  ALLOW_TCP_FORWARDING="local"
fi

if [[ "$RP_FILTER" == "auto" ]]; then
  # Modo laxo en workstation: evita descartes con VPN y rutas asimétricas
  [[ "$PROFILE" == "workstation" ]] && RP_FILTER=2 || RP_FILTER=1
fi

if [[ "$KERNEL_SYSRQ" == "auto" ]]; then
  # 4 = solo el subconjunto de teclado (útil ante un cuelgue de la sesión
  # gráfica con acceso físico). En servidor no aporta nada: 0.
  [[ "$PROFILE" == "workstation" ]] && KERNEL_SYSRQ=4 || KERNEL_SYSRQ=0
fi

if [[ "$DOCKER_COMPAT" == "auto" ]]; then
  if command -v docker >/dev/null 2>&1 || [[ -S /var/run/docker.sock ]]; then
    DOCKER_COMPAT=1
  else
    DOCKER_COMPAT=0
  fi
fi

if [[ "$CLAMAV_QUARANTINE" == "auto" ]]; then
  [[ "$PROFILE" == "server" ]] && CLAMAV_QUARANTINE=1 || CLAMAV_QUARANTINE=0
fi

if [[ "$APPARMOR_EXTRA_PROFILES" == "auto" ]]; then
  [[ "$PROFILE" == "workstation" ]] && APPARMOR_EXTRA_PROFILES=1 || APPARMOR_EXTRA_PROFILES=1
fi

if [[ "$ENABLE_SANDBOX" == "auto" ]]; then
  [[ "$PROFILE" == "workstation" ]] && ENABLE_SANDBOX=1 || ENABLE_SANDBOX=0
fi

# ¿Hay entorno gráfico? Determina si tiene sentido instalar Flatpak/Flatseal.
HAS_DESKTOP=0
if [[ -d /usr/share/xsessions ]] || [[ -d /usr/share/wayland-sessions ]] \
   || command -v gnome-session >/dev/null 2>&1 || command -v startplasma-x11 >/dev/null 2>&1; then
  HAS_DESKTOP=1
fi

if [[ "$INSTALL_FLATPAK" == "auto" ]]; then
  if [[ "$ENABLE_SANDBOX" == "1" && "$HAS_DESKTOP" == "1" ]]; then
    INSTALL_FLATPAK=1
  else
    INSTALL_FLATPAK=0
  fi
fi

# ─────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────
clear
printf "\033[1;31m"
printf "\033[0m"
printf "\033[1;37m         Debian 13 — Hardening Completo Interactivo  ·  v2.1\033[0m\n"
printf "\033[0;90m         Backups y log en: %s\033[0m\n\n" "$BACKUP_DIR"

printf "\033[1;33m  ADVERTENCIA:\033[0m Este script modificará configuraciones críticas del sistema.\n"
printf "  Asegúrate de tener acceso de recuperación (consola física o KVM) antes de continuar.\n\n"
printf "  Configuración activa:\n"
printf "    • Perfil            : \033[1m%s\033[0m\n" "$PROFILE"
printf "    • Usuario admin     : \033[1m%s\033[0m\n" "$ADMIN_USER"
printf "    • SSH               : \033[1m%s\033[0m" "$([[ "$ENABLE_SSH" == "1" ]] && echo "activado" || echo "DESACTIVADO")"
[[ "$ENABLE_SSH" == "1" ]] && printf " (puerto %s, 2FA=%s)" "$SSH_PORT" "$ENABLE_SSH_2FA"
printf "\n"
printf "    • SSH CIDRs         : \033[1m%s\033[0m\n" "${ALLOW_SSH_CIDRS:-<cualquiera>}"
printf "    • HTTP / HTTPS      : \033[1m%s / %s\033[0m\n" "$ALLOW_HTTP" "$ALLOW_HTTPS"
printf "    • Compat. Docker    : \033[1m%s\033[0m\n" "$DOCKER_COMPAT"
printf "    • rp_filter         : \033[1m%s\033[0m (%s)\n" "$RP_FILTER" "$([[ "$RP_FILTER" == "2" ]] && echo "laxo" || echo "estricto")"
printf "    • AppArmor extra    : \033[1m%s\033[0m (modo %s, enforce-all=%s)\n" "$APPARMOR_EXTRA_PROFILES" "$APPARMOR_EXTRA_MODE" "$APPARMOR_ENFORCE_ALL"
printf "    • auditd            : \033[1m%s\033[0m (nivel %s, inmutable=%s)\n" "$ENABLE_AUDITD" "$AUDIT_LEVEL" "$AUDIT_IMMUTABLE"
printf "    • Sandboxing        : \033[1m%s\033[0m (flatpak=%s, lockdown=%s, firejail=%s)\n" "$ENABLE_SANDBOX" "$INSTALL_FLATPAK" "$FLATPAK_LOCKDOWN" "$ENABLE_FIREJAIL"
printf "    • ClamAV / AIDE     : \033[1m%s / %s\033[0m (cuarentena=%s)\n" "$ENABLE_CLAMAV" "$ENABLE_AIDE" "$CLAMAV_QUARANTINE"
printf "\n"

if [[ "$PROFILE" == "workstation" ]]; then
  printf "\033[0;36m  Perfil ESCRITORIO: se conservan avahi/cups/bluetooth, mDNS abierto,\n"
  printf "  ClamAV bajo demanda (solo informe) y AIDE con exclusiones de /home.\033[0m\n\n"
else
  printf "\033[0;36m  Perfil SERVIDOR: servicios de escritorio desactivados, ClamAV\n"
  printf "  residente con cuarentena y AIDE con cobertura completa.\033[0m\n\n"
fi

if [[ "$ASSUME_YES" != "1" ]]; then
  printf "  ¿Deseas continuar? [s/N] "
  read -r CONFIRM
  if [[ ! "$CONFIRM" =~ ^[sS]$ ]]; then
    echo "Cancelado."
    exit 0
  fi
fi

export DEBIAN_FRONTEND=noninteractive


# ═════════════════════════════════════════════════════════════
# PASO 1: Estado inicial
# ═════════════════════════════════════════════════════════════
step "Estado inicial del sistema"
result_block "$(uname -a)"
result_block "$(. /etc/os-release && echo "$PRETTY_NAME")"
info "Interfaces de red:"
result_block "$(ip -brief addr show 2>&1 || true)"
ok "Estado del sistema registrado."


# ═════════════════════════════════════════════════════════════
# PASO 2: Actualización completa
# ═════════════════════════════════════════════════════════════
step "Actualización completa de paquetes"
run_logged "apt-get update" apt-get update
run_logged "apt-get full-upgrade" apt-get -y full-upgrade


# ═════════════════════════════════════════════════════════════
# PASO 3: Herramientas de seguridad
# ═════════════════════════════════════════════════════════════
step "Instalación de herramientas base de seguridad"

PKGS=(
  sudo vim curl gnupg lsb-release ca-certificates
  nftables fail2ban apparmor apparmor-utils
  unattended-upgrades apt-listchanges
  logwatch lynis mokutil
)
[[ "$ENABLE_SSH"   == "1" ]] && PKGS+=(openssh-server)
[[ "$ENABLE_AIDE"  == "1" ]] && PKGS+=(aide aide-common)

# ── Perfiles de AppArmor (v2.1) ──
# apparmor-profiles       → perfiles adicionales en /etc/apparmor.d (modo complain)
# apparmor-profiles-extra → perfiles de escritorio en /usr/share/apparmor/extra-profiles
if [[ "$APPARMOR_EXTRA_PROFILES" == "1" ]]; then
  for p in apparmor-profiles apparmor-profiles-extra; do
    if pkg_exists "$p"; then
      PKGS+=("$p")
    else
      warn "Paquete '$p' no disponible en los repositorios — omitido."
    fi
  done
fi

# ── auditd (v2.1) ──
if [[ "$ENABLE_AUDITD" == "1" ]]; then
  PKGS+=(auditd)
  pkg_exists audispd-plugins && PKGS+=(audispd-plugins)
fi

# ── Sandboxing (v2.1) ──
if [[ "$ENABLE_SANDBOX" == "1" ]]; then
  PKGS+=(bubblewrap)
fi

if [[ "$ENABLE_CLAMAV" == "1" ]]; then
  PKGS+=(clamav clamav-freshclam)
  # El demonio residente solo tiene sentido si algo lo consulta (MTA, Samba…)
  [[ "$PROFILE" == "server" ]] && PKGS+=(clamav-daemon)
fi

run_logged "Instalando ${#PKGS[@]} paquetes" apt-get -y install "${PKGS[@]}"


# ═════════════════════════════════════════════════════════════
# PASO 4: Servicios innecesarios (según perfil)
# ═════════════════════════════════════════════════════════════
step "Desactivar servicios innecesarios (perfil: $PROFILE)"

if [[ "$PROFILE" == "server" ]]; then
  UNNECESSARY_SERVICES=(avahi-daemon cups cups-browsed bluetooth rpcbind ModemManager)
else
  UNNECESSARY_SERVICES=(rpcbind)
  info "Perfil escritorio: se conservan avahi-daemon, cups y bluetooth."
  info "  avahi  → resolución .local, descubrimiento de impresoras/escáneres"
  info "  cups   → impresión"
  info "  bluetooth → auriculares, teclado y ratón"
fi

for svc in "${UNNECESSARY_SERVICES[@]}"; do
  if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 && \
     systemctl is-enabled "$svc" >/dev/null 2>&1; then
    systemctl disable --now "$svc" >>"$LOGFILE" 2>&1 || true
    ok "$svc desactivado."
  else
    info "$svc no está activo o no existe — omitido."
  fi
done


# ═════════════════════════════════════════════════════════════
# PASO 5: Actualizaciones automáticas
# ═════════════════════════════════════════════════════════════
step "Configurar actualizaciones automáticas de seguridad"

dpkg-reconfigure -f noninteractive unattended-upgrades >>"$LOGFILE" 2>&1 || true

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat > /etc/apt/apt.conf.d/51fortknox-unattended <<EOF
// Fort-Knox: comportamiento de unattended-upgrades
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
EOF

ok "Actualizaciones automáticas configuradas (sin reinicio automático)."
info "Prueba en seco:  unattended-upgrade --dry-run --debug"


# ═════════════════════════════════════════════════════════════
# PASO 6: Logs persistentes con límite
# ═════════════════════════════════════════════════════════════
step "Habilitar logs persistentes de journald (con tope de tamaño)"

mkdir -p /var/log/journal
[[ -f /etc/systemd/journald.conf ]] && cp -a /etc/systemd/journald.conf "$BACKUP_DIR/journald.conf.bak"

mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-fortknox.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1G
SystemMaxFileSize=128M
MaxRetentionSec=1month
ForwardToSyslog=no
EOF

systemctl restart systemd-journald
ok "journald persistente, con tope de 1 GB y retención de 1 mes."
info "ForwardToSyslog=no evita duplicar todos los logs si hay rsyslog instalado."


# ═════════════════════════════════════════════════════════════
# PASO 7: Hardening del kernel (sysctl)
# ═════════════════════════════════════════════════════════════
step "Endurecimiento del kernel con parámetros sysctl"

SYSCTL_H="/etc/sysctl.d/99-fortknox.conf"
[[ -f "$SYSCTL_H" ]] && cp -a "$SYSCTL_H" "$BACKUP_DIR/99-fortknox.conf.bak"

cat > "$SYSCTL_H" <<EOF
# ── Fort-Knox: Hardening de kernel y red ─────────────────────
# Generado por fort-knox v2.1 · perfil: $PROFILE

# ── Red IPv4 ─────────────────────────────────────────────────
net.ipv4.ip_forward = $([[ "$DOCKER_COMPAT" == "1" ]] && echo 1 || echo 0)

# Filtrado de ruta inversa. 1=estricto, 2=laxo (recomendado con VPN)
net.ipv4.conf.all.rp_filter = $RP_FILTER
net.ipv4.conf.default.rp_filter = $RP_FILTER

net.ipv4.tcp_syncookies = 1

# NOTA: tcp_timestamps se deja en 1. Ponerlo a 0 desactiva PAWS y degrada la
# estimación de RTT; desde Linux 4.10 el offset se aleatoriza por conexión,
# así que el beneficio anti-fingerprinting es despreciable.
net.ipv4.tcp_timestamps = 1

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Red IPv6 ─────────────────────────────────────────────────
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# accept_ra: dejar en 1 si dependes de SLAAC/RA en tu red
net.ipv6.conf.all.accept_ra = 1
net.ipv6.conf.default.accept_ra = 1

# ── Kernel ───────────────────────────────────────────────────
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.core_uses_pid = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0

# sysrq: 4 = solo el subconjunto de teclado (rescatar una sesión gráfica
# colgada con acceso físico). 0 lo desactiva por completo — recomendado si
# el equipo puede quedar desatendido en un sitio público.
kernel.sysrq = $KERNEL_SYSRQ

# ptrace_scope: 1 permite depurar procesos hijos (gdb, strace sobre lo que
# tú lanzas) pero impide adjuntarse a procesos ajenos. 0 lo desactiva.
kernel.yama.ptrace_scope = $PTRACE_SCOPE

# perf_event_paranoid: 2 conserva 'perf' en espacio de usuario.
# Subir a 3 endurece más pero rompe el perfilado.
kernel.perf_event_paranoid = 2

# ── Sistema de archivos ──────────────────────────────────────
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF

sysctl --system >>"$LOGFILE" 2>&1
ok "Parámetros sysctl aplicados y persistentes en $SYSCTL_H"

if [[ "$DOCKER_COMPAT" == "1" ]]; then
  warn "ip_forward=1 porque Docker lo necesita para el enrutado de contenedores."
fi
if [[ "$PTRACE_SCOPE" != "0" ]]; then
  info "ptrace_scope=$PTRACE_SCOPE — si necesitas 'gdb -p PID' sobre procesos ajenos, usa PTRACE_SCOPE=0."
fi
info "kernel.sysrq=$KERNEL_SYSRQ — cámbialo con KERNEL_SYSRQ=0|4 si tu escenario físico es distinto."


# ═════════════════════════════════════════════════════════════
# PASO 8: SSH
# ═════════════════════════════════════════════════════════════
if [[ "$ENABLE_SSH" == "1" ]]; then
step "Endurecimiento del servidor SSH"

# Debian coloca 'Include sshd_config.d/*.conf' al principio de sshd_config y en
# SSH gana el PRIMER valor obtenido: editar el fichero principal puede quedar
# anulado silenciosamente. Por eso se escribe en un drop-in.
SSHD_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN="$SSHD_DIR/99-fortknox.conf"
mkdir -p "$SSHD_DIR"
cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
[[ -f "$SSHD_DROPIN" ]] && cp -a "$SSHD_DROPIN" "$BACKUP_DIR/99-fortknox-sshd.conf.bak"

if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
  warn "sshd_config no incluye sshd_config.d/*.conf — añadiendo el Include al principio."
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi

# ── Instalación de la clave pública ──
USER_HOME=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"

if [[ -n "$PUBKEY" ]]; then
  info "Instalando clave pública para $ADMIN_USER..."
  install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$USER_HOME/.ssh"
  touch "$AUTH_KEYS"
  grep -qxF "$PUBKEY" "$AUTH_KEYS" || echo "$PUBKEY" >> "$AUTH_KEYS"
  chmod 600 "$AUTH_KEYS"
  chown "$ADMIN_USER:$ADMIN_USER" "$AUTH_KEYS"
  ok "Clave instalada en $AUTH_KEYS"
fi

# ── Guardia anti-lockout: no desactivar contraseñas sin clave válida ──
KEY_COUNT=0
[[ -f "$AUTH_KEYS" ]] && KEY_COUNT=$(grep -cvE '^\s*(#|$)' "$AUTH_KEYS" || true)

if [[ "$KEY_COUNT" -eq 0 ]]; then
  err "No hay ninguna clave en $AUTH_KEYS."
  err "Desactivar PasswordAuthentication ahora te dejaría sin acceso SSH."
  err "Soluciones:"
  err "  a) Relanza con PUBKEY=\"ssh-ed25519 AAAA...\""
  err "  b) Copia la clave antes:  ssh-copy-id -p 22 $ADMIN_USER@<host>"
  exit 1
fi
ok "Verificadas $KEY_COUNT clave(s) autorizada(s) para $ADMIN_USER."

# ── Configuración ──
{
  echo "# Fort-Knox v2.1 — generado $(date -Is)"
  echo "Port ${SSH_PORT}"
  [[ "$ALLOW_SSH_PORT_22" == "1" ]] && echo "Port 22"
  cat <<EOF
Protocol 2
AddressFamily any

PermitRootLogin no
AllowUsers ${ADMIN_USER}
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
UsePAM yes

X11Forwarding no
AllowTcpForwarding ${ALLOW_TCP_FORWARDING}
AllowAgentForwarding no
PermitTunnel no

ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# Algoritmos modernos
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

LogLevel VERBOSE
EOF
} > "$SSHD_DROPIN"

# ── 2FA ──
if [[ "$ENABLE_SSH_2FA" == "1" ]]; then
  info "Configurando TOTP (Google Authenticator)..."
  run_logged "Instalando libpam-google-authenticator" \
    apt-get -y install libpam-google-authenticator

  PAM_SSHD="/etc/pam.d/sshd"
  cp -a "$PAM_SSHD" "$BACKUP_DIR/sshd.pam.bak"
  grep -q 'pam_google_authenticator.so' "$PAM_SSHD" || \
    echo "auth required pam_google_authenticator.so nullok" >> "$PAM_SSHD"

  # Exigir keyboard-interactive con KbdInteractive desactivado hacía que el 2FA
  # nunca funcionase. ChallengeResponseAuthentication está obsoleto desde 8.7.
  cat >> "$SSHD_DROPIN" <<'EOF'

# ── 2FA (TOTP) ──
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
EOF
  warn "Ejecuta ahora:  sudo -u ${ADMIN_USER} -H google-authenticator"
  warn "Con 'nullok', los usuarios sin TOTP registrado aún entran. Quítalo cuando"
  warn "todos estén enrolados, o quedará como un bypass permanente."
else
  echo "KbdInteractiveAuthentication no" >> "$SSHD_DROPIN"
fi

chmod 600 "$SSHD_DROPIN"

info "Validando configuración de sshd..."
if ! sshd -t 2>>"$LOGFILE"; then
  err "¡La configuración de sshd es inválida! Revirtiendo..."
  rm -f "$SSHD_DROPIN"
  result_block "$(tail -10 "$LOGFILE")"
  exit 1
fi
ok "Configuración validada por 'sshd -t'."

info "Configuración efectiva (extracto):"
result_block "$(sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|allowusers|allowtcpforwarding)' || true)"

systemctl reload ssh 2>/dev/null || systemctl restart ssh
ok "SSH endurecido y activo en el puerto $SSH_PORT"
warn "MANTÉN ESTA SESIÓN ABIERTA. Abre otra terminal y prueba:"
warn "    ssh -p $SSH_PORT $ADMIN_USER@<host>"
pause_for_read

else
step "SSH (omitido)"
info "ENABLE_SSH=0 — perfil escritorio sin servidor SSH."
if systemctl is-enabled ssh >/dev/null 2>&1; then
  systemctl disable --now ssh >>"$LOGFILE" 2>&1 || true
  ok "Servicio ssh detenido y desactivado."
else
  info "El servicio ssh no estaba activo."
fi
info "Para activarlo más adelante:  ENABLE_SSH=1 PUBKEY=\"ssh-ed25519 ...\" $0"
fi


# ═════════════════════════════════════════════════════════════
# PASO 9: Cortafuegos nftables
# ═════════════════════════════════════════════════════════════
step "Configurar cortafuegos nftables (deny-by-default)"

NFT_CONF="/etc/nftables.conf"
[[ -f "$NFT_CONF" ]] && cp -a "$NFT_CONF" "$BACKUP_DIR/nftables.conf.bak"

# ── Reglas SSH: discriminar familia según el CIDR ──
SSH_ALLOW_RULES=""
add_ssh_rule() {
  local cidr="$1" port="$2"
  if [[ -z "$cidr" ]]; then
    SSH_ALLOW_RULES+="    tcp dport ${port} ct state new accept"$'\n'
  elif [[ "$cidr" == *:* ]]; then
    SSH_ALLOW_RULES+="    ip6 saddr ${cidr} tcp dport ${port} ct state new accept"$'\n'
  else
    SSH_ALLOW_RULES+="    ip saddr ${cidr} tcp dport ${port} ct state new accept"$'\n'
  fi
}

if [[ "$ENABLE_SSH" == "1" ]]; then
  PORTS_TO_OPEN=("$SSH_PORT")
  [[ "$ALLOW_SSH_PORT_22" == "1" ]] && PORTS_TO_OPEN+=(22)

  for p in "${PORTS_TO_OPEN[@]}"; do
    if [[ -n "$ALLOW_SSH_CIDRS" ]]; then
      IFS=',' read -ra CIDRS <<< "$ALLOW_SSH_CIDRS"
      for c in "${CIDRS[@]}"; do
        add_ssh_rule "$(echo "$c" | xargs)" "$p"
      done
    else
      add_ssh_rule "" "$p"
    fi
  done
fi

EXTRA_RULES=""
[[ "$ALLOW_HTTP"  == "1" ]] && EXTRA_RULES+="    tcp dport 80 ct state new accept"$'\n'
[[ "$ALLOW_HTTPS" == "1" ]] && EXTRA_RULES+="    tcp dport 443 ct state new accept"$'\n'
[[ -n "$EXTRA_TCP_PORTS" ]] && EXTRA_RULES+="    tcp dport { ${EXTRA_TCP_PORTS} } ct state new accept"$'\n'
[[ -n "$EXTRA_UDP_PORTS" ]] && EXTRA_RULES+="    udp dport { ${EXTRA_UDP_PORTS} } ct state new accept"$'\n'

# mDNS: imprescindible en escritorio para .local, impresoras y descubrimiento
DESKTOP_RULES=""
if [[ "$PROFILE" == "workstation" ]]; then
  DESKTOP_RULES+="    udp dport 5353 accept comment \"mDNS / Avahi\""$'\n'
  DESKTOP_RULES+="    udp dport 1900 accept comment \"SSDP / UPnP\""$'\n'
fi

# ── Compatibilidad con Docker ──
# 'flush ruleset' borra las reglas que Docker inyecta vía iptables-nft, dejando
# los contenedores sin red. Aquí usamos una tabla propia.
if [[ "$DOCKER_COMPAT" == "1" ]]; then
  FLUSH_DIRECTIVE="# Sin 'flush ruleset': preserva las reglas de Docker/libvirt
table inet fortknox
delete table inet fortknox"
  FORWARD_POLICY="accept"
  FORWARD_COMMENT="# policy accept: Docker gestiona el reenvío con sus propias reglas"
else
  FLUSH_DIRECTIVE="flush ruleset"
  FORWARD_POLICY="drop"
  FORWARD_COMMENT=""
fi

cat > "$NFT_CONF" <<EOF
#!/usr/sbin/nft -f
# Fort-Knox v2.1 · perfil: $PROFILE · generado $(date -Is)

${FLUSH_DIRECTIVE}

table inet fortknox {

  set allowed_icmp_v4 {
    type icmp_type
    elements = { echo-request, echo-reply, time-exceeded, destination-unreachable, parameter-problem }
  }

  # Tipos de ICMPv6 que NO deben limitarse: rompen el descubrimiento de vecinos
  set icmpv6_essential {
    type icmpv6_type
    elements = {
      nd-neighbor-solicit, nd-neighbor-advert,
      nd-router-solicit, nd-router-advert,
      packet-too-big, destination-unreachable,
      time-exceeded, parameter-problem
    }
  }

  chain input {
    type filter hook input priority filter; policy drop;

    iif lo accept
    ct state established,related accept
    ct state invalid drop comment "descarta paquetes invalid antes que nada"

    # ICMPv6 esencial sin límite de tasa
    icmpv6 type @icmpv6_essential accept
    icmpv6 type echo-request limit rate 10/second accept
    ip protocol icmp icmp type @allowed_icmp_v4 limit rate 10/second accept

    # Cliente DHCP
    udp sport 67 udp dport 68 accept comment "DHCPv4"
    udp sport 547 udp dport 546 accept comment "DHCPv6"

${DESKTOP_RULES}${SSH_ALLOW_RULES}${EXTRA_RULES}
    # Registro limitado de descartes (útil para diagnosticar)
    limit rate 5/minute burst 10 packets log prefix "fortknox-drop: " level info
  }

  chain forward {
    ${FORWARD_COMMENT}
    type filter hook forward priority filter; policy ${FORWARD_POLICY};
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}
EOF

info "Validando sintaxis con 'nft -c'..."
if ! nft -c -f "$NFT_CONF" 2>>"$LOGFILE"; then
  err "Las reglas nftables son inválidas. NO se han aplicado."
  result_block "$(tail -10 "$LOGFILE")"
  err "Fichero conservado para inspección: $NFT_CONF"
  exit 1
fi
ok "Sintaxis de nftables validada."

nft -f "$NFT_CONF"
systemctl enable --now nftables >>"$LOGFILE" 2>&1

info "Reglas activas:"
result_block "$(nft list table inet fortknox 2>&1 | head -50 || true)"
ok "Cortafuegos nftables activo."

if [[ "$DOCKER_COMPAT" == "1" ]]; then
  warn "Modo Docker: la cadena forward está en 'accept' y no se hace flush del"
  warn "ruleset. Docker gestiona su propio filtrado. Si más adelante desinstalas"
  warn "Docker, relanza con DOCKER_COMPAT=0 para endurecer el reenvío."
fi


# ═════════════════════════════════════════════════════════════
# PASO 10: fail2ban
# ═════════════════════════════════════════════════════════════
step "Configurar fail2ban"

if [[ "$ENABLE_SSH" == "1" ]]; then
  mkdir -p /etc/fail2ban/jail.d

  # Detectar redes locales para no autobloquearse
  LOCAL_NETS=$(ip -4 -brief addr show scope global 2>/dev/null \
    | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}' | tr -d '\n' || true)

  # 'logpath' y 'backend = systemd' son mutuamente excluyentes; con backend
  # systemd la ruta se ignora. banaction acorde a nftables.
  cat > /etc/fail2ban/jail.d/fortknox.local <<EOF
[DEFAULT]
backend   = systemd
banaction = nftables[type=multiport]
ignoreip  = 127.0.0.1/8 ::1 ${LOCAL_NETS}
bantime   = 3600
findtime  = 600
maxretry  = 5

[sshd]
enabled = true
port    = ${SSH_PORT}$([[ "$ALLOW_SSH_PORT_22" == "1" ]] && echo ",22")
EOF

  systemctl enable --now fail2ban >>"$LOGFILE" 2>&1

  sleep 2
  OUT=$(fail2ban-client status sshd 2>&1 || true)
  result_block "$OUT"
  ok "fail2ban activo — 5 intentos fallidos en 10 min → 1 h de bloqueo."
  info "Redes exentas: 127.0.0.1/8 ::1 ${LOCAL_NETS}"
else
  systemctl disable --now fail2ban >>"$LOGFILE" 2>&1 || true
  info "Sin SSH expuesto — fail2ban desactivado (no hay servicio que proteger)."
fi


# ═════════════════════════════════════════════════════════════
# PASO 11: AppArmor  (AMPLIADO en v2.1)
# ═════════════════════════════════════════════════════════════
step "AppArmor — activación, perfiles adicionales y modo de aplicación"

# Declarado aquí para que el resumen final pueda consultarlo aunque el paso
# se salte por completo (AppArmor inactivo en el kernel).
AA_COPIED=()

systemctl enable --now apparmor >>"$LOGFILE" 2>&1 || true

# ── 11.1 · ¿Es AppArmor realmente un LSM activo? ──
# Si el kernel arrancó sin AppArmor, todo lo demás es decorativo.
AA_ACTIVE=0
if [[ -r /sys/kernel/security/lsm ]] && grep -q 'apparmor' /sys/kernel/security/lsm; then
  AA_ACTIVE=1
  ok "AppArmor está entre los LSM activos del kernel."
  result_block "LSM activos: $(cat /sys/kernel/security/lsm)"
else
  err "AppArmor NO aparece en /sys/kernel/security/lsm."
  warn "Comprueba la línea de arranque:  cat /proc/cmdline"
  warn "Debería contener (o no contradecir):  apparmor=1 security=apparmor"
  warn "Si tienes 'security=selinux' o 'apparmor=0' en GRUB, quítalo y reinicia."
fi

if [[ "$AA_ACTIVE" == "1" ]]; then

  # ── 11.2 · Desplegar perfiles extra para binarios realmente instalados ──
  # apparmor-profiles-extra deja sus perfiles en /usr/share/apparmor/extra-profiles
  # SIN activarlos. Aquí se copian a /etc/apparmor.d solo los que corresponden a
  # un binario presente, y solo si superan la validación del parser.
  AA_EXTRA_DIR="/usr/share/apparmor/extra-profiles"

  if [[ "$APPARMOR_EXTRA_PROFILES" == "1" && -d "$AA_EXTRA_DIR" ]]; then
    info "Buscando perfiles extra aplicables en $AA_EXTRA_DIR ..."
    for pf in "$AA_EXTRA_DIR"/*; do
      [[ -f "$pf" ]] || continue
      base="$(basename "$pf")"
      # Descarta documentación y ficheros que no son perfiles
      case "$base" in
        README*|*.md|*.txt|*.gz) continue ;;
      esac
      # Ya existe un perfil con ese nombre en /etc/apparmor.d → no lo pisamos
      [[ -e "/etc/apparmor.d/$base" ]] && continue

      # Convención de nombres: usr.bin.firefox → /usr/bin/firefox
      bin="/$(printf '%s' "$base" | tr '.' '/')"
      [[ -x "$bin" ]] || continue

      # Validación sintáctica sin cargar en el kernel
      if ! apparmor_parser -Q "$pf" >>"$LOGFILE" 2>&1; then
        warn "Perfil '$base' no valida con este kernel — omitido."
        continue
      fi

      cp -n "$pf" "/etc/apparmor.d/$base"
      AA_COPIED+=("$base")
      info "  + $base  →  $bin"
    done

    if [[ ${#AA_COPIED[@]} -gt 0 ]]; then
      for base in "${AA_COPIED[@]}"; do
        if [[ "$APPARMOR_EXTRA_MODE" == "enforce" ]]; then
          aa-enforce "/etc/apparmor.d/$base" >>"$LOGFILE" 2>&1 || \
            warn "No se pudo poner en enforce: $base"
        else
          aa-complain "/etc/apparmor.d/$base" >>"$LOGFILE" 2>&1 || \
            warn "No se pudo poner en complain: $base"
        fi
      done
      ok "${#AA_COPIED[@]} perfil(es) extra desplegados en modo $APPARMOR_EXTRA_MODE."
      if [[ "$APPARMOR_EXTRA_MODE" == "complain" ]]; then
        info "En 'complain' no bloquean: solo registran lo que habrían bloqueado."
        info "Usa el equipo unos días con normalidad y luego revisa:"
        info "    aa-logprof                 # ajusta los perfiles con lo aprendido"
        info "    aa-enforce /etc/apparmor.d/usr.bin.firefox   # cuando esté afinado"
      else
        warn "Perfiles extra en ENFORCE desde ya: si alguna aplicación deja de"
        warn "abrir ficheros o de imprimir, revísalo con 'journalctl -k | grep DENIED'"
        warn "y vuelve atrás con 'aa-complain /etc/apparmor.d/<perfil>'."
      fi
    else
      info "No había perfiles extra nuevos aplicables (o ya estaban desplegados)."
    fi
  elif [[ "$APPARMOR_EXTRA_PROFILES" == "1" ]]; then
    warn "$AA_EXTRA_DIR no existe — ¿se instaló apparmor-profiles-extra?"
  fi

  # ── 11.3 · Recargar y aplicar ──
  systemctl reload apparmor >>"$LOGFILE" 2>&1 || \
    systemctl restart apparmor >>"$LOGFILE" 2>&1 || \
    warn "No se pudo recargar AppArmor — revisa $LOGFILE"

  # ── 11.4 · Promoción opcional de TODO complain → enforce ──
  if [[ "$APPARMOR_ENFORCE_ALL" == "1" ]]; then
    warn "APPARMOR_ENFORCE_ALL=1 — promoviendo perfiles en complain a enforce."
    if command -v python3 >/dev/null 2>&1; then
      COMPLAIN_LIST=$(aa-status --json 2>/dev/null | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for n, m in (d.get("profiles") or {}).items():
    if m == "complain":
        print(n)
' || true)
      PROMOTED=0
      while IFS= read -r prof; do
        [[ -z "$prof" ]] && continue
        # Respeta el modo elegido para los perfiles extra recién desplegados
        skip=0
        if [[ ${#AA_COPIED[@]} -gt 0 ]]; then
          for base in "${AA_COPIED[@]}"; do
            [[ "/$(printf '%s' "$base" | tr '.' '/')" == "$prof" ]] && skip=1
          done
        fi
        [[ "$skip" == "1" && "$APPARMOR_EXTRA_MODE" == "complain" ]] && continue
        if aa-enforce "$prof" >>"$LOGFILE" 2>&1; then
          PROMOTED=$((PROMOTED + 1))
        fi
      done <<< "$COMPLAIN_LIST"
      ok "$PROMOTED perfil(es) promovidos a enforce."
      warn "Si algo se rompe:  aa-complain <perfil>   y revisa 'journalctl -k -g DENIED'"
    else
      warn "python3 no disponible — no se pudo listar los perfiles en complain."
    fi
  else
    info "APPARMOR_ENFORCE_ALL=0 — no se tocan los modos de los perfiles del sistema."
  fi

  # ── 11.5 · Informe ──
  OUT=$(aa-status --verbose 2>&1 | head -6 || true)
  result_block "$OUT"

  PROFILES_ENFORCE=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in enforce mode)' || echo "?")
  PROFILES_COMPLAIN=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in complain mode)' || echo "?")
  ok "AppArmor activo — $PROFILES_ENFORCE perfiles en enforce, $PROFILES_COMPLAIN en complain."

  # Procesos con puertos abiertos que NO están confinados: la lista de deberes
  if command -v aa-unconfined >/dev/null 2>&1; then
    info "Procesos en escucha SIN confinar (candidatos a perfil propio):"
    result_block "$(aa-unconfined 2>/dev/null | head -20 || echo '(sin datos)')"
  fi

  info "Denegaciones recientes:  journalctl -k -g 'apparmor=\"DENIED\"' --since today"
else
  PROFILES_ENFORCE="0"
  PROFILES_COMPLAIN="0"
  warn "Se omite el despliegue de perfiles: AppArmor no está activo en el kernel."
fi


# ═════════════════════════════════════════════════════════════
# PASO 12: auditd  (NUEVO en v2.1)
# ═════════════════════════════════════════════════════════════
if [[ "$ENABLE_AUDITD" == "1" ]]; then
step "Auditoría del kernel con auditd (nivel: $AUDIT_LEVEL)"

AUDIT_RULES_D="/etc/audit/rules.d"
AUDIT_RULES="$AUDIT_RULES_D/99-fortknox.rules"
mkdir -p "$AUDIT_RULES_D"
[[ -f "$AUDIT_RULES" ]] && cp -a "$AUDIT_RULES" "$BACKUP_DIR/99-fortknox.rules.bak"
[[ -f /etc/audit/auditd.conf ]] && cp -a /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.bak"

# Las reglas con -F arch=b64 no cargan en un sistema de 32 bits
AUDIT_ARCH="b64"
[[ "$(getconf LONG_BIT 2>/dev/null || echo 64)" == "32" ]] && AUDIT_ARCH="b32"

{
cat <<EOF
## Fort-Knox v2.1 — reglas de auditoría · perfil: $PROFILE · nivel: $AUDIT_LEVEL
## Generado $(date -Is). Recarga con:  augenrules --load

## ── Control ──────────────────────────────────────────────────
-D
-b 8192
--backlog_wait_time 60000
# -f 1 = registrar el fallo en printk. NO usar 2 (kernel panic).
-f 1

## No auditar el propio ruido de auditd
-a never,exit -F arch=$AUDIT_ARCH -F exe=/usr/sbin/auditd -S all

## ── Identidad y autenticación ────────────────────────────────
-w /etc/passwd  -p wa -k identidad
-w /etc/shadow  -p wa -k identidad
-w /etc/group   -p wa -k identidad
-w /etc/gshadow -p wa -k identidad
-w /etc/sudoers   -p wa -k escalada
-w /etc/sudoers.d/ -p wa -k escalada
-w /etc/pam.d/     -p wa -k autenticacion
-w /etc/security/  -p wa -k autenticacion
-w /var/log/lastlog -p wa -k sesiones
-w /var/run/faillock -p wa -k sesiones

## ── SSH ──────────────────────────────────────────────────────
-w /etc/ssh/sshd_config    -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh

## ── Kernel, módulos y arranque ───────────────────────────────
-w /etc/sysctl.conf -p wa -k kernel
-w /etc/sysctl.d/   -p wa -k kernel
-w /etc/modprobe.d/ -p wa -k modulos
-a always,exit -F arch=$AUDIT_ARCH -S init_module,finit_module,delete_module -k modulos
-w /boot/ -p wa -k arranque

## ── Superficie de seguridad ──────────────────────────────────
-w /etc/nftables.conf -p wa -k firewall
-w /etc/apparmor.d/   -p wa -k apparmor
-w /etc/audit/        -p wa -k auditoria
-w /etc/fail2ban/     -p wa -k fail2ban
-w /etc/aide/         -p wa -k integridad

## ── Tiempo (manipularlo es un clásico anti-forense) ──────────
-a always,exit -F arch=$AUDIT_ARCH -S adjtimex,settimeofday,clock_settime -k tiempo
-w /etc/localtime -p wa -k tiempo

## ── Tareas programadas ───────────────────────────────────────
-w /etc/crontab -p wa -k programado
-w /etc/cron.d/ -p wa -k programado
-w /etc/systemd/system/ -p wa -k programado
-w /usr/local/sbin/ -p wa -k programado

## ── Montajes (medios extraíbles, exfiltración) ───────────────
-a always,exit -F arch=$AUDIT_ARCH -S mount,umount2 -F auid>=1000 -F auid!=unset -k montaje
EOF

if [[ "$AUDIT_LEVEL" == "strict" ]]; then
cat <<EOF

## ═══ NIVEL STRICT ════════════════════════════════════════════
## Genera MUCHO volumen en escritorio: el navegador prueba rutas
## inexistentes constantemente. Revisa el tamaño de /var/log/audit.

## Accesos denegados (reconocimiento)
-a always,exit -F arch=$AUDIT_ARCH -S open,openat,openat2,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k acceso_denegado
-a always,exit -F arch=$AUDIT_ARCH -S open,openat,openat2,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k acceso_denegado

## Cambios de permisos y propietario
-a always,exit -F arch=$AUDIT_ARCH -S chmod,fchmod,fchmodat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k permisos
-a always,exit -F arch=$AUDIT_ARCH -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k permisos

## Borrado y renombrado por usuarios
-a always,exit -F arch=$AUDIT_ARCH -S unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k borrado

## Ejecución de binarios privilegiados concretos
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privilegiado
-a always,exit -F path=/usr/bin/su   -F perm=x -F auid>=1000 -F auid!=unset -k privilegiado
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privilegiado
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=unset -k privilegiado
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privilegiado
EOF
fi

if [[ "$AUDIT_IMMUTABLE" == "1" ]]; then
cat <<'EOF'

## ── Configuración inmutable: requiere REINICIO para cambiar reglas ──
-e 2
EOF
else
cat <<'EOF'

## -e 1 = auditoría activa, reglas modificables en caliente.
## Pon AUDIT_IMMUTABLE=1 para '-e 2' (a prueba de manipulación, pero
## cualquier cambio de reglas exigirá reiniciar).
-e 1
EOF
fi
} > "$AUDIT_RULES"

chmod 600 "$AUDIT_RULES"
ok "Reglas escritas en $AUDIT_RULES"

# ── Tuning de auditd.conf: nunca acciones destructivas ──
# Debian trae valores razonables, pero admin_space_left_action=SINGLE o HALT
# convertirían un disco lleno en una caída del equipo. Se fijan explícitamente.
set_conf_key /etc/audit/auditd.conf max_log_file 50
set_conf_key /etc/audit/auditd.conf num_logs 5
set_conf_key /etc/audit/auditd.conf max_log_file_action ROTATE
set_conf_key /etc/audit/auditd.conf space_left 500
set_conf_key /etc/audit/auditd.conf space_left_action SYSLOG
set_conf_key /etc/audit/auditd.conf admin_space_left 200
set_conf_key /etc/audit/auditd.conf admin_space_left_action SYSLOG
set_conf_key /etc/audit/auditd.conf disk_full_action SUSPEND
set_conf_key /etc/audit/auditd.conf disk_error_action SYSLOG
set_conf_key /etc/audit/auditd.conf flush INCREMENTAL_ASYNC
ok "auditd.conf ajustado (máx. ~250 MB de logs, sin acciones destructivas)."

systemctl enable auditd >>"$LOGFILE" 2>&1 || true
systemctl restart auditd >>"$LOGFILE" 2>&1 || service auditd restart >>"$LOGFILE" 2>&1 || true

if augenrules --load >>"$LOGFILE" 2>&1; then
  ok "Reglas cargadas con augenrules."
else
  warn "augenrules devolvió error — revisa $LOGFILE (¿-e 2 de una carga previa?)"
fi

sleep 1
AUDIT_LOADED=$(auditctl -l 2>/dev/null | grep -cv '^No rules$' || echo 0)
AUDIT_STATUS=$(auditctl -s 2>/dev/null | tr '\n' ' ' || echo "n/d")
result_block "Reglas cargadas: ${AUDIT_LOADED}
${AUDIT_STATUS}"

ok "auditd operativo."
info "Consultas útiles:"
info "    ausearch -k escalada -i --start today      # cambios en sudoers"
info "    ausearch -m AVC -i --start today           # denegaciones de AppArmor"
info "    aureport --summary -i                      # resumen global"
info "    aureport --auth --summary -i               # autenticaciones"
warn "Con auditd en marcha, los mensajes de audit dejan de aparecer en journald:"
warn "las denegaciones de AppArmor pasan a consultarse con 'ausearch -m AVC'."

else
step "auditd (omitido)"
info "ENABLE_AUDITD=0"
fi


# ═════════════════════════════════════════════════════════════
# PASO 13: Secure Boot
# ═════════════════════════════════════════════════════════════
step "Verificar estado del Arranque Seguro"

if command -v mokutil >/dev/null 2>&1; then
  SB_STATE=$(mokutil --sb-state 2>&1 || true)
  result_block "$SB_STATE"
  if echo "$SB_STATE" | grep -qi "enabled"; then
    info "Secure Boot activo: los módulos DKMS (NVIDIA, VirtualBox…) necesitan"
    info "firma e inscripción MOK, o no cargarán."
  fi
else
  warn "mokutil no disponible."
fi


# ═════════════════════════════════════════════════════════════
# PASO 14: ClamAV  (unidad ENDURECIDA en v2.1)
# ═════════════════════════════════════════════════════════════
if [[ "$ENABLE_CLAMAV" == "1" ]]; then
step "Configurar ClamAV (escaneo programado con unidad confinada)"

QUARANTINE_DIR="/var/lib/fortknox/cuarentena"
CLAM_TMPDIR="/var/lib/fortknox/tmp"
mkdir -p "$QUARANTINE_DIR" "$CLAM_TMPDIR"
chmod 700 "$QUARANTINE_DIR" "$CLAM_TMPDIR"

systemctl stop clamav-freshclam >>"$LOGFILE" 2>&1 || true
info "Actualizando firmas (puede tardar varios minutos)..."
freshclam >>"$LOGFILE" 2>&1 || warn "freshclam devolvió error — revisa $LOGFILE"
systemctl enable --now clamav-freshclam >>"$LOGFILE" 2>&1 || true
ok "Firmas actualizadas y servicio freshclam activo."

SCAN_PATHS="/home /tmp /var/tmp /srv"

# ── Modo cuarentena vs solo informe ──
# En escritorio, --move sobre /home significa que un falso positivo te quita un
# fichero de trabajo sin avisar. Por defecto (workstation) solo se informa.
if [[ "$CLAMAV_QUARANTINE" == "1" ]]; then
  CLAM_ACTION="--move=\"$QUARANTINE_DIR\""
  info "Modo CUARENTENA: lo detectado se mueve a $QUARANTINE_DIR"
else
  CLAM_ACTION=""
  info "Modo INFORME: se registra lo detectado, no se mueve nada."
  info "Actívalo con CLAMAV_QUARANTINE=1 si prefieres aislamiento automático."
fi

cat > /usr/local/sbin/fortknox-clamscan <<EOF
#!/bin/bash
# Escaneo programado — Fort-Knox v2.1
LOG=/var/log/fortknox-clamscan.log
{
  echo "=== \$(date -Is) — inicio ==="
  # --tempdir fuera de /tmp: con ProtectSystem=strict el /tmp del servicio es
  # de solo lectura, y clamscan necesita escribir al desempaquetar archivos.
  nice -n 19 ionice -c3 clamscan -ri --stdout \\
    --tempdir="$CLAM_TMPDIR" \\
    --exclude-dir='^/(proc|sys|dev|run)' \\
    --exclude-dir='/\.cache' \\
    --exclude-dir='/\.local/share/Trash' \\
    --exclude-dir='/var/lib/docker' \\
    --exclude-dir='/var/lib/flatpak' \\
    $CLAM_ACTION \\
    $SCAN_PATHS
  echo "=== \$(date -Is) — fin (código \$?) ==="
} >> "\$LOG" 2>&1
EOF
chmod 750 /usr/local/sbin/fortknox-clamscan

# ── Unidad systemd confinada ──
# Es un oneshot que corre como root y recorre todo /home: exactamente el tipo
# de servicio que merece confinamiento. Las directivas se ajustan al modo:
#   · informe    → ProtectHome=read-only y solo /var/log escribible
#   · cuarentena → hace falta escritura en las rutas escaneadas para mover
{
cat <<'EOF'
[Unit]
Description=Fort-Knox - escaneo ClamAV programado
Documentation=man:clamscan(1)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fortknox-clamscan
Nice=19
IOSchedulingClass=idle

# ── Confinamiento (v2.1) ──
NoNewPrivileges=yes
AmbientCapabilities=
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
# @resources NO se bloquea: contiene setpriority/ioprio_set, que usan el
# 'nice'/'ionice' del propio script (y sin ellos el escaneo penaliza el equipo).
SystemCallFilter=~@privileged @mount @debug @swap @reboot @clock
# PrivateTmp=no a propósito: el escaneo debe ver el /tmp real.
PrivateTmp=no
PrivateDevices=yes
# ClamAV 1.x ya no usa el JIT de LLVM, así que W^X no le afecta.
# Si algún día el escaneo falla con SIGSEGV, comenta la línea siguiente.
MemoryDenyWriteExecute=yes
EOF

if [[ "$CLAMAV_QUARANTINE" == "1" ]]; then
cat <<'EOF'
# Cuarentena activa: hace falta escritura (y borrado) en las rutas escaneadas
# para poder mover lo detectado, de ahí las capacidades DAC adicionales.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER
ProtectHome=no
ReadWritePaths=/var/log /var/lib/fortknox /home /srv /tmp /var/tmp
EOF
else
cat <<'EOF'
# Solo informe: basta con poder leerlo todo. Sin escritura fuera del log y
# del directorio temporal propio.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
ProtectHome=read-only
ReadWritePaths=/var/log /var/lib/fortknox/tmp
ReadOnlyPaths=/srv
EOF
fi

cat <<'EOF'

[Install]
WantedBy=multi-user.target
EOF
} > /etc/systemd/system/fortknox-clamscan.service

cat > /etc/logrotate.d/fortknox-clamscan <<'EOF'
/var/log/fortknox-clamscan.log {
    monthly
    rotate 6
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

cat > /etc/systemd/system/fortknox-clamscan.timer <<'EOF'
[Unit]
Description=Fort-Knox - escaneo ClamAV semanal

[Timer]
OnCalendar=Sun 03:00
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload

# Verificación: si la unidad no valida, no la dejamos programada
if systemd-analyze verify /etc/systemd/system/fortknox-clamscan.service >>"$LOGFILE" 2>&1; then
  ok "Unidad fortknox-clamscan.service validada."
else
  warn "systemd-analyze verify emitió avisos — revisa $LOGFILE"
fi

systemctl enable --now fortknox-clamscan.timer >>"$LOGFILE" 2>&1
ok "Escaneo semanal programado (domingos 03:00)."

if command -v systemd-analyze >/dev/null 2>&1; then
  SEC_SCORE=$(systemd-analyze security fortknox-clamscan.service --no-pager 2>/dev/null | tail -3 || true)
  info "Exposición de la unidad según systemd-analyze:"
  result_block "${SEC_SCORE:-(no disponible)}"
  info "Compara con la v2.0 (sin directivas): pasaba de ~9.6 'UNSAFE' a la baja."
fi

info "Prueba manual del escaneo:  systemctl start fortknox-clamscan.service"
info "Resultado:                  tail -f /var/log/fortknox-clamscan.log"

if [[ "$PROFILE" == "workstation" ]]; then
  info "Sin clamav-daemon: en escritorio el demonio residente consume ~1 GB de"
  info "RAM sin utilidad salvo que configures on-access con clamonacc."
fi
else
step "ClamAV (omitido)"
info "ENABLE_CLAMAV=0"
fi


# ═════════════════════════════════════════════════════════════
# PASO 15: Sandboxing de aplicaciones  (NUEVO en v2.1, opcional)
# ═════════════════════════════════════════════════════════════
if [[ "$ENABLE_SANDBOX" == "1" ]]; then
step "Aislamiento de aplicaciones (bubblewrap / Flatpak)"

info "El perímetro de red y la integridad del sistema ya están cubiertos."
info "Este paso ataca la superficie real de un escritorio: navegador, visor de"
info "PDF y cliente de correo procesando ficheros de origen ajeno."

# ── 15.1 · bubblewrap + envoltorio fortknox-sandbox ──
if command -v bwrap >/dev/null 2>&1; then
  cat > /usr/local/bin/fortknox-sandbox <<'SANDBOX'
#!/usr/bin/env bash
# =============================================================================
# fortknox-sandbox — ejecuta un programa en un contenedor bubblewrap desechable
# -----------------------------------------------------------------------------
# Uso:
#   fortknox-sandbox [opciones] COMANDO [ARGS...]
#
# Opciones:
#   --net            Permite red (por defecto SIN red)
#   --dbus           Expone el bus de sesión (muchas apps GUI lo exigen)
#   --ro RUTA        Monta RUTA en solo lectura dentro del sandbox
#   --rw RUTA        Monta RUTA en lectura/escritura dentro del sandbox
#   -h, --help       Esta ayuda
#
# El HOME es un directorio temporal que se destruye al salir: lo que la
# aplicación escriba en ~ desaparece. Los ficheros que quieras que vea se
# pasan con --ro / --rw.
#
# Ejemplos:
#   fortknox-sandbox --ro ~/Descargas/dudoso.pdf evince ~/Descargas/dudoso.pdf
#   fortknox-sandbox --net --dbus firefox
#
# Aviso: bubblewrap aísla, no es una máquina virtual. Un 0-day del kernel
# sigue siendo un 0-day del kernel.
# =============================================================================
set -euo pipefail

WITH_NET=0
WITH_DBUS=0
BINDS=()

usage() { sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --net)  WITH_NET=1; shift ;;
    --dbus) WITH_DBUS=1; shift ;;
    --ro)   [[ $# -ge 2 ]] || { echo "--ro requiere una ruta" >&2; exit 1; }
            p=$(readlink -f "$2"); BINDS+=(--ro-bind "$p" "$p"); shift 2 ;;
    --rw)   [[ $# -ge 2 ]] || { echo "--rw requiere una ruta" >&2; exit 1; }
            p=$(readlink -f "$2"); BINDS+=(--bind "$p" "$p"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "Opción desconocida: $1" >&2; exit 1 ;;
    *)  break ;;
  esac
done

[[ $# -ge 1 ]] || { usage; exit 1; }

UID_N=$(id -u)
RT="${XDG_RUNTIME_DIR:-/run/user/$UID_N}"
SBHOME=$(mktemp -d "${TMPDIR:-/tmp}/fortknox-sandbox.XXXXXXXX")
cleanup() { rm -rf "$SBHOME"; }
trap cleanup EXIT

NETARGS=(--unshare-net)
[[ "$WITH_NET" == "1" ]] && NETARGS=()

DBUSARGS=()
[[ "$WITH_DBUS" == "1" ]] && DBUSARGS=(--ro-bind-try "$RT/bus" "$RT/bus")

exec bwrap \
  --ro-bind /usr /usr \
  --ro-bind /etc /etc \
  --symlink usr/lib  /lib \
  --symlink usr/lib64 /lib64 \
  --symlink usr/bin  /bin \
  --symlink usr/sbin /sbin \
  --proc /proc \
  --dev /dev \
  --dev-bind-try /dev/dri /dev/dri \
  --tmpfs /var \
  --ro-bind-try /var/lib/dbus/machine-id /var/lib/dbus/machine-id \
  --tmpfs /tmp \
  --ro-bind-try /tmp/.X11-unix /tmp/.X11-unix \
  --tmpfs /run \
  --dir "$RT" \
  --ro-bind-try "$RT/wayland-0" "$RT/wayland-0" \
  --ro-bind-try "$RT/pipewire-0" "$RT/pipewire-0" \
  --ro-bind-try "$RT/pulse" "$RT/pulse" \
  "${DBUSARGS[@]}" \
  --bind "$SBHOME" "$HOME" \
  --setenv HOME "$HOME" \
  --setenv XDG_RUNTIME_DIR "$RT" \
  "${BINDS[@]}" \
  --unshare-user --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup \
  "${NETARGS[@]}" \
  --cap-drop ALL \
  --new-session \
  --die-with-parent \
  -- "$@"
SANDBOX
  chmod 755 /usr/local/bin/fortknox-sandbox
  ok "Envoltorio instalado: /usr/local/bin/fortknox-sandbox"
  info "Abrir un PDF de origen dudoso sin red y con HOME desechable:"
  info "    fortknox-sandbox --ro ~/Descargas/x.pdf evince ~/Descargas/x.pdf"
  info "Ayuda completa:  fortknox-sandbox --help"
else
  warn "bwrap no está disponible — se omite el envoltorio fortknox-sandbox."
fi

# ── 15.2 · Flatpak + Flathub ──
if [[ "$INSTALL_FLATPAK" == "1" ]]; then
  run_logged "Instalando flatpak" apt-get -y install flatpak

  # Integración con el centro de software si el escritorio es GNOME
  if command -v gnome-shell >/dev/null 2>&1 && pkg_exists gnome-software-plugin-flatpak; then
    apt-get -y install gnome-software-plugin-flatpak >>"$LOGFILE" 2>&1 || true
  fi
  if command -v plasmashell >/dev/null 2>&1 && pkg_exists plasma-discover-backend-flatpak; then
    apt-get -y install plasma-discover-backend-flatpak >>"$LOGFILE" 2>&1 || true
  fi

  if flatpak remote-add --if-not-exists flathub \
       https://flathub.org/repo/flathub.flatpakrepo >>"$LOGFILE" 2>&1; then
    ok "Remoto Flathub configurado."
  else
    warn "No se pudo añadir Flathub — ¿sin red o proxy? Revisa $LOGFILE"
  fi

  if [[ "$INSTALL_FLATSEAL" == "1" ]]; then
    info "Instalando Flatseal (descarga el runtime de GNOME la primera vez)..."
    if flatpak install -y --noninteractive flathub com.github.tchx84.Flatseal \
         >>"$LOGFILE" 2>&1; then
      ok "Flatseal instalado — gestiona los permisos de cada Flatpak con interfaz."
    else
      warn "Flatseal no se pudo instalar. Manualmente:"
      warn "    flatpak install flathub com.github.tchx84.Flatseal"
    fi
  else
    info "INSTALL_FLATSEAL=0 — instálalo cuando quieras con:"
    info "    flatpak install flathub com.github.tchx84.Flatseal"
  fi

  # ── 15.3 · Script de recorte de permisos (NO se aplica solo) ──
  cat > /usr/local/sbin/fortknox-flatpak-lockdown <<'LOCKDOWN'
#!/usr/bin/env bash
# =============================================================================
# fortknox-flatpak-lockdown — recorta los permisos GLOBALES de Flatpak
# -----------------------------------------------------------------------------
# Estas anulaciones se aplican a TODAS las aplicaciones Flatpak. Es un cambio
# consciente: algunas apps dejarán de ver ficheros hasta que les des acceso
# concreto con Flatseal o con 'flatpak override --user <app> --filesystem=...'.
#
# Revertir todo:   flatpak override --reset
# Ver lo aplicado: flatpak override --show
# =============================================================================
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Ejecútalo como root (afecta a las anulaciones del sistema)." >&2; exit 1; }

echo "Aplicando recorte global de permisos Flatpak..."

# Sin acceso al sistema de ficheros del host ni al home completo.
# Las apps seguirán pudiendo abrir ficheros a través de los portales XDG
# (el diálogo 'Abrir' del escritorio), que conceden acceso fichero a fichero.
flatpak override --nofilesystem=host
flatpak override --nofilesystem=home

# X11 permite a cualquier cliente espiar el teclado de los demás. Con
# fallback-x11 solo se usa X11 cuando no hay Wayland disponible.
flatpak override --nosocket=x11
flatpak override --socket=fallback-x11
flatpak override --socket=wayland

# Sin acceso directo a todos los dispositivos; se conserva la GPU.
flatpak override --nodevice=all
flatpak override --device=dri

echo
echo "Hecho. Estado actual:"
flatpak override --show
echo
echo "Si una aplicación deja de encontrar tus ficheros, concédele acceso"
echo "concreto en lugar de revertirlo todo, por ejemplo:"
echo "    flatpak override org.libreoffice.LibreOffice --filesystem=~/Documentos"
LOCKDOWN
  chmod 750 /usr/local/sbin/fortknox-flatpak-lockdown
  ok "Script de recorte disponible: /usr/local/sbin/fortknox-flatpak-lockdown"

  if [[ "$FLATPAK_LOCKDOWN" == "1" ]]; then
    warn "FLATPAK_LOCKDOWN=1 — aplicando el recorte global ahora."
    if /usr/local/sbin/fortknox-flatpak-lockdown >>"$LOGFILE" 2>&1; then
      ok "Permisos globales de Flatpak recortados."
      info "Revertir:  flatpak override --reset"
    else
      warn "El recorte falló — revisa $LOGFILE"
    fi
  else
    info "FLATPAK_LOCKDOWN=0 — el recorte NO se ha aplicado (decisión tuya)."
    info "Ejecútalo cuando quieras:  sudo fortknox-flatpak-lockdown"
  fi
else
  info "Flatpak no se instala (INSTALL_FLATPAK=0 o sin entorno gráfico)."
fi

# ── 15.4 · firejail: solo bajo petición expresa ──
if [[ "$ENABLE_FIREJAIL" == "1" ]]; then
  warn "firejail se instala con SUID root: históricamente ha acumulado CVEs de"
  warn "escalada local. Es una herramienta de aislamiento cuyo propio binario"
  warn "amplía la superficie de ataque. Para uso diario, bubblewrap o Flatpak"
  warn "cubren lo mismo sin ese riesgo."
  run_logged "Instalando firejail" apt-get -y install firejail firejail-profiles
  info "Reduce el riesgo quitando el SUID si no necesitas sus funciones de red:"
  info "    dpkg-statoverride --update --add root root 0755 /usr/bin/firejail"
else
  info "firejail omitido (ENABLE_FIREJAIL=0) — bubblewrap cubre el caso sin SUID."
fi

info "Resumen del aislamiento disponible ahora:"
info "  · fortknox-sandbox     → cualquier binario, HOME desechable, sin red"
info "  · Flatpak + Flatseal   → apps de escritorio con permisos por aplicación"
info "  · AppArmor (PASO 11)   → confinamiento de los binarios del sistema"

else
step "Sandboxing de aplicaciones (omitido)"
info "ENABLE_SANDBOX=0 — actívalo con ENABLE_SANDBOX=1."
fi


# ═════════════════════════════════════════════════════════════
# PASO 16: AIDE  (al final: el baseline debe reflejar el estado definitivo)
# ═════════════════════════════════════════════════════════════
if [[ "$ENABLE_AIDE" == "1" ]]; then
step "Inicializar AIDE (baseline de integridad)"

if [[ -d /etc/aide/aide.conf.d ]]; then
  cat > /etc/aide/aide.conf.d/99-fortknox <<'EOF'
# Fort-Knox: exclusiones para reducir ruido
!/home
!/root/fortknox-backups
!/var/log
!/var/lib/fortknox
!/var/cache
!/var/tmp
!/tmp
!/srv/datos
!/var/lib/docker
!/var/lib/containerd
!/var/lib/clamav
# v2.1
!/var/log/audit
!/var/lib/flatpak
!/var/lib/aide
!/var/lib/systemd
EOF
  ok "Exclusiones escritas en /etc/aide/aide.conf.d/99-fortknox"
  if [[ "$PROFILE" == "workstation" ]]; then
    info "En escritorio, /home cambia constantemente: sin excluirlo los informes"
    info "diarios de AIDE son ilegibles. Ajusta la lista a tus montajes de datos."
  fi
fi

info "Ejecutando aideinit — puede tardar varios minutos..."
if aideinit -y -f >>"$LOGFILE" 2>&1; then
  ok "Baseline de AIDE generado."
else
  warn "aideinit devolvió error — revisa $LOGFILE"
fi

if [[ -f /var/lib/aide/aide.db.new ]]; then
  cp -a /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  ok "Base de datos activa en /var/lib/aide/aide.db"
  info "Comprobación manual:  aide --check --config /etc/aide/aide.conf"
  info "AIDE dice QUÉ cambió; auditd (PASO 12) dice CUÁNDO y QUIÉN."
else
  warn "No se generó aide.db.new — revisa la instalación."
fi
else
step "AIDE (omitido)"
info "ENABLE_AIDE=0"
fi


# ═════════════════════════════════════════════════════════════
# PASO 17: Auditoría Lynis
# ═════════════════════════════════════════════════════════════
step "Auditoría de seguridad con Lynis"

info "Analizando el sistema..."
lynis audit system --quick --quiet >>"$LOGFILE" 2>&1 || true

HARDENING_INDEX=$(grep -oP 'Hardening index : \K\d+' /var/log/lynis.log 2>/dev/null | tail -1 || echo "?")
ok "Auditoría completada. Índice de endurecimiento: $HARDENING_INDEX/100"
info "Sugerencias:  grep -E '^\\s*(\\*|-) ' /var/log/lynis-report.dat"
info "Informe completo en /var/log/lynis.log"


# ═════════════════════════════════════════════════════════════
# PASO 18: Resumen
# ═════════════════════════════════════════════════════════════
step "Resumen del estado del sistema"

printf "\n\033[1;37m  ╔══════════════════════════════════════════════════╗\033[0m\n"
printf "\033[1;37m  ║        HARDENING COMPLETADO CORRECTAMENTE        ║\033[0m\n"
printf "\033[1;37m  ╚══════════════════════════════════════════════════╝\033[0m\n\n"

printf "  %-25s \033[1m%s\033[0m\n" "Perfil:"            "$PROFILE"
printf "  %-25s \033[1m%s\033[0m\n" "Usuario admin:"     "$ADMIN_USER"
printf "  %-25s \033[1m%s\033[0m\n" "SSH:"               "$([[ "$ENABLE_SSH" == "1" ]] && echo "puerto $SSH_PORT" || echo "desactivado")"
printf "  %-25s \033[1m%s\033[0m\n" "SSH CIDRs:"         "${ALLOW_SSH_CIDRS:-<cualquiera>}"
printf "  %-25s \033[1m%s\033[0m\n" "2FA:"               "$ENABLE_SSH_2FA"
printf "  %-25s \033[1m%s / %s\033[0m\n" "HTTP / HTTPS:"  "$ALLOW_HTTP" "$ALLOW_HTTPS"
printf "  %-25s \033[1m%s\033[0m\n" "Compat. Docker:"    "$DOCKER_COMPAT"
printf "  %-25s \033[1m%s enforce / %s complain\033[0m\n" "AppArmor:" "${PROFILES_ENFORCE:-?}" "${PROFILES_COMPLAIN:-?}"
printf "  %-25s \033[1m%s\033[0m\n" "auditd:"            "$([[ "$ENABLE_AUDITD" == "1" ]] && echo "activo (${AUDIT_LOADED:-?} reglas, nivel $AUDIT_LEVEL)" || echo "desactivado")"
printf "  %-25s \033[1m%s\033[0m\n" "Sandboxing:"        "$([[ "$ENABLE_SANDBOX" == "1" ]] && echo "bwrap$([[ "$INSTALL_FLATPAK" == "1" ]] && echo " + flatpak")" || echo "desactivado")"
printf "  %-25s \033[1m%s\033[0m\n" "ClamAV:"            "$([[ "$ENABLE_CLAMAV" == "1" ]] && echo "semanal ($([[ "$CLAMAV_QUARANTINE" == "1" ]] && echo "cuarentena" || echo "solo informe"))" || echo "desactivado")"
printf "  %-25s \033[1m%s\033[0m\n" "Índice Lynis:"      "$HARDENING_INDEX/100"
printf "  %-25s \033[1m%s\033[0m\n" "Backups:"           "$BACKUP_DIR"
printf "  %-25s \033[1m%s\033[0m\n" "Log completo:"      "$LOGFILE"
printf "\n"

info "Servicios en escucha:"
result_block "$(ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}' | sort -u | head -25 || true)"

info "Cadena input de nftables:"
result_block "$(nft list chain inet fortknox input 2>&1 | head -30 || true)"

if [[ "$ENABLE_SSH" == "1" ]]; then
  info "Estado de fail2ban:"
  result_block "$(fail2ban-client status 2>&1 || true)"
fi

printf "\n"
if [[ "$ENABLE_SSH" == "1" ]]; then
  warn "MANTÉN ESTA SESIÓN ABIERTA hasta verificar:  ssh -p $SSH_PORT $ADMIN_USER@<host>"
fi
[[ "$ENABLE_SSH_2FA" == "1" ]] && \
  warn "2FA activo: ejecuta 'sudo -u $ADMIN_USER -H google-authenticator' y luego retira 'nullok' de /etc/pam.d/sshd"

if [[ "$ENABLE_AUDITD" == "1" && "$AUDIT_IMMUTABLE" == "1" ]]; then
  warn "auditd en modo inmutable (-e 2): cualquier cambio de reglas necesita reinicio."
fi

if [[ "$APPARMOR_EXTRA_MODE" == "complain" && ${#AA_COPIED[@]} -gt 0 ]]; then
  printf "\n\033[0;36m  Siguiente paso con AppArmor (una o dos semanas de uso normal):\033[0m\n"
  printf "    1. aa-logprof                        # revisa lo aprendido en complain\n"
  printf "    2. aa-enforce /etc/apparmor.d/<perfil>   # promueve los ya afinados\n"
  printf "    3. O relanza con:  APPARMOR_EXTRA_MODE=enforce %s\n" "$0"
fi

printf "\n\033[0;36m  Pendiente fuera del alcance de este script:\033[0m\n"
printf "    • Cifrado de disco (LUKS) — se decide en el instalador, no después\n"
printf "    • Contraseña de GRUB\n"
printf "    • Opciones nodev,nosuid,noexec en /tmp y /var/tmp\n"
printf "    • usbguard, si te preocupa el acceso físico\n"
printf "    • Envío de los logs de auditd a un colector externo (tu SIEM)\n"
printf "\n\033[1;32m  Fort-Knox v2.1 completado.\033[0m\n\n"

exit 0
