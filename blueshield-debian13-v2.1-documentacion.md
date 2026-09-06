# BlueShield Debian 13 — Manual de referencia

**Versión del script:** 2.1
**Fichero:** `blueshield-debian13_v2.1.sh`
**Sistema objetivo:** Debian 13 "Trixie" (amd64; las reglas de auditoría se adaptan a 32 bits)
**Autor de la documentación:** revisión técnica sobre el script de Eloy
**Última actualización:** septiembre de 2026

---

## Índice

1. [Qué es y qué no es](#1-qué-es-y-qué-no-es)
2. [Modelo de amenaza y alcance](#2-modelo-de-amenaza-y-alcance)
3. [Requisitos y primera ejecución](#3-requisitos-y-primera-ejecución)
4. [Perfiles: `workstation` y `server`](#4-perfiles-workstation-y-server)
5. [Referencia completa de variables](#5-referencia-completa-de-variables)
6. [Los 18 pasos, uno a uno](#6-los-18-pasos-uno-a-uno)
7. [Ficheros y unidades que toca](#7-ficheros-y-unidades-que-toca)
8. [Herramientas que instala](#8-herramientas-que-instala)
9. [Verificación posterior](#9-verificación-posterior)
10. [Operación diaria](#10-operación-diaria)
11. [Resolución de problemas](#11-resolución-de-problemas)
12. [Reversión](#12-reversión)
13. [Anexo A — Decisiones de diseño](#anexo-a--decisiones-de-diseño)
14. [Anexo B — Historial de versiones y bugs corregidos](#anexo-b--historial-de-versiones-y-bugs-corregidos)
15. [Anexo C — Fuera de alcance](#anexo-c--fuera-de-alcance)

---

## 1. Qué es y qué no es

BlueShield es un script de endurecimiento (*hardening*) **interactivo, idempotente y con backups automáticos** para Debian 13. Aplica en un solo paso una línea base de seguridad razonable sobre una instalación limpia, y puede relanzarse tantas veces como haga falta: cada ejecución vuelve a dejar el sistema en el estado descrito por sus variables, sin duplicar reglas ni acumular configuración.

**Lo que es:**

- Una línea base reproducible y auditable, con todo el razonamiento escrito en los propios ficheros que genera.
- Un script defensivo: valida antes de aplicar (`sshd -t`, `nft -c`, `apparmor_parser -Q`, `systemd-analyze verify`) y aborta sin dejar el sistema a medias.
- Un punto de partida documentado, no un producto cerrado. Está pensado para leerse y ajustarse.

**Lo que no es:**

- No es un antivirus ni un EDR. ClamAV aquí es un escaneo semanal de higiene, no detección en tiempo real.
- No sustituye al cifrado de disco, a las copias de seguridad ni a la actualización disciplinada.
- No protege contra un atacante con acceso físico y tiempo. Para eso hacen falta LUKS, contraseña de GRUB y Secure Boot con claves propias.
- No garantiza cumplimiento normativo (CIS, ANSSI, ENS). Se acerca a varios de sus controles, pero no los certifica.

### Idempotencia: qué significa aquí exactamente

Relanzar el script es seguro. Concretamente:

- Los ficheros de configuración se **reescriben completos** desde cero (`>`), no se van añadiendo líneas. Un `99-blueshield.conf` no crece a cada ejecución.
- Los servicios se activan con `enable --now`, que no falla si ya estaban activos.
- Los perfiles de AppArmor se copian con `cp -n` y solo si no existe ya un perfil con ese nombre en `/etc/apparmor.d`.
- La clave pública SSH se añade a `authorized_keys` solo si no está ya (`grep -qxF`).
- Cada ejecución crea un **directorio de backup nuevo** con marca de tiempo, así que no se pisan los respaldos anteriores.

La única operación no idempotente por naturaleza es `aideinit`: regenera el baseline de integridad completo, lo cual es lo correcto — tras cambiar la configuración del sistema, el baseline anterior ya no vale.

---

## 2. Modelo de amenaza y alcance

Merece la pena tener claro contra qué protege cada bloque, porque no todos protegen contra lo mismo.

| Bloque | Amenaza que mitiga | Amenaza que NO mitiga |
|---|---|---|
| nftables (PASO 9) | Servicios expuestos por accidente, escaneo desde la red local | Nada que entre por el navegador (tráfico saliente permitido) |
| sysctl (PASO 7) | Suplantación de rutas, redirecciones ICMP, fuga de punteros del kernel | Vulnerabilidades del propio kernel |
| SSH + fail2ban (PASOS 8, 10) | Fuerza bruta y credenciales débiles | Robo de la clave privada del cliente |
| AppArmor (PASO 11) | Que un binario comprometido haga más de lo que le corresponde | Binarios sin perfil (la mayoría de las apps de escritorio) |
| auditd (PASO 12) | *Nada.* Es detección, no prevención | Todo — pero deja rastro de lo que pasó |
| ClamAV (PASO 14) | Malware conocido, sobre todo en tránsito hacia Windows | Malware dirigido, cualquier cosa reciente |
| AIDE (PASO 16) | Persistencia de un atacante en ficheros del sistema | Persistencia en `/home`, que está excluido |
| Sandboxing (PASO 15) | Que un PDF o una web comprometan el resto de tu `$HOME` | Un 0-day del kernel: bubblewrap no es una VM |
| Actualizaciones (PASO 5) | La causa real de la mayoría de compromisos | Vulnerabilidades sin parche |

Si tuviera que ordenarlos por retorno real en un escritorio de productividad: **actualizaciones automáticas > sandboxing de aplicaciones > nftables > AppArmor > auditd > AIDE > ClamAV**.

---

## 3. Requisitos y primera ejecución

### Requisitos

- Debian 13 (funciona en 12 con cambios menores; no se ha probado en derivadas).
- Ejecución como `root` (directamente o vía `sudo`).
- Acceso de recuperación: consola física, KVM o IPMI. **Esto no es opcional en un servidor remoto.**
- Conexión a Internet para `apt`, `freshclam` y, si procede, Flathub.

### Primera ejecución en un escritorio

```bash
chmod +x blueshield-debian13_v2.1.sh
sudo ./blueshield-debian13_v2.1.sh
```

El script muestra un banner con toda la configuración resuelta (incluidos los valores `auto` ya decididos) y pide confirmación antes de tocar nada. Léelo: es la última oportunidad de ver qué va a pasar.

### Primera ejecución en un servidor remoto

El orden importa. Copia primero la clave, comprueba que entra, y solo entonces endurece:

```bash
# Desde tu equipo
ssh-copy-id -p 22 usuario@servidor

# En el servidor
sudo PROFILE=server \
     ALLOW_SSH_CIDRS="192.168.1.0/24" \
     SSH_PORT=2222 \
     ./blueshield-debian13_v2.1.sh
```

El PASO 8 **se detiene y aborta** si no encuentra ninguna clave en `authorized_keys`, precisamente para que desactivar `PasswordAuthentication` no te deje fuera. Después de aplicarlo, hace una pausa y te obliga a probar la conexión desde otra terminal antes de continuar. Mantén la sesión original abierta hasta que la nueva funcione.

### Ejecución desatendida

```bash
sudo ASSUME_YES=1 PROFILE=workstation ./blueshield-debian13_v2.1.sh
```

`ASSUME_YES=1` salta la confirmación inicial y todas las pausas. Úsalo solo cuando ya lo hayas ejecutado a mano al menos una vez en un sistema equivalente.

### Dónde queda el rastro

Cada ejecución crea `/root/blueshield-backups/AAAA-MM-DD-HHMMSS/` con:

- `blueshield.log` — salida completa de todos los comandos.
- Copias `.bak` de los ficheros que se modifican (no de los que se crean nuevos).

---

## 4. Perfiles: `workstation` y `server`

Un mismo script, dos comportamientos. El perfil no es cosmético: cambia decisiones de seguridad reales.

| Aspecto | `workstation` | `server` |
|---|---|---|
| SSH | Desactivado (`ENABLE_SSH=0`) | Activo en el puerto 2222 |
| avahi, cups, bluetooth | **Se conservan** | Se desactivan |
| rpcbind, ModemManager | Se desactiva rpcbind | Se desactivan ambos |
| mDNS (5353) y SSDP (1900) | Abiertos en el cortafuegos | Cerrados |
| `rp_filter` | `2` (laxo) | `1` (estricto) |
| `kernel.sysrq` | `4` (subconjunto de teclado) | `0` |
| ClamAV | Sin demonio residente, escaneo **solo informe** | Con `clamav-daemon`, **cuarentena activa** |
| AIDE | `/home` excluido | `/home` excluido igualmente, resto completo |
| Sandboxing (PASO 15) | Activo | Desactivado |
| Perfiles AppArmor extra | Se despliegan | Se despliegan |

La lógica de fondo: en un escritorio, romper la impresión, el Bluetooth o el descubrimiento de red tiene un coste diario que supera con creces la ganancia de seguridad de apagarlos. En un servidor, esos servicios son superficie de ataque sin contrapartida.

---

## 5. Referencia completa de variables

Todas se pasan como variables de entorno delante del script:

```bash
sudo PROFILE=server AUDIT_LEVEL=strict ./blueshield-debian13_v2.1.sh
```

### Generales

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `PROFILE` | `workstation` \| `server` | `workstation` | Perfil de configuración. Ver sección 4. |
| `ADMIN_USER` | nombre de usuario | `$SUDO_USER`, o el primer UID ≥ 1000 | Usuario que conservará acceso SSH y para el que se instala la clave. |
| `ASSUME_YES` | `0` \| `1` | `0` | Salta confirmación y pausas. |

### SSH

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `ENABLE_SSH` | `1` \| `0` \| `auto` | `auto` | `auto` → 1 en server, 0 en workstation. |
| `SSH_PORT` | puerto | `2222` | Puerto de escucha. |
| `ALLOW_SSH_CIDRS` | lista separada por comas | vacío (cualquiera) | Restringe el origen. Acepta IPv4 e IPv6 mezclados: `"192.168.1.0/24,fd00::/8"`. |
| `ALLOW_SSH_PORT_22` | `0` \| `1` | `0` | Mantiene también el 22 abierto (útil durante la transición). |
| `ALLOW_TCP_FORWARDING` | `yes` \| `no` \| `local` \| `auto` | `auto` → `local` | `local` permite túneles `-L` (llegar a interfaces web del homelab) pero no `-R`. |
| `PUBKEY` | `"ssh-ed25519 AAAA..."` | vacío | Instala la clave en `authorized_keys` del `ADMIN_USER`. |
| `ENABLE_SSH_2FA` | `0` \| `1` | `0` | Añade TOTP (Google Authenticator) sobre la clave pública. |

### Cortafuegos

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `ALLOW_HTTP` | `0` \| `1` | `0` | Abre el 80/tcp. |
| `ALLOW_HTTPS` | `0` \| `1` | `0` | Abre el 443/tcp. |
| `EXTRA_TCP_PORTS` | `"8006,9000"` | vacío | Puertos TCP adicionales. |
| `EXTRA_UDP_PORTS` | `"51820"` | vacío | Puertos UDP adicionales (p. ej. WireGuard). |
| `DOCKER_COMPAT` | `1` \| `0` \| `auto` | `auto` | Detecta Docker y evita el `flush ruleset` que dejaría los contenedores sin red. |

### Kernel

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `RP_FILTER` | `1` \| `2` \| `auto` | `auto` | `2` (laxo) en workstation: evita descartes con VPN y rutas asimétricas. |
| `PTRACE_SCOPE` | `0`–`3` | `1` | `1` permite depurar procesos hijos propios, no ajenos. `0` si necesitas `gdb -p PID`. |
| `KERNEL_SYSRQ` | `0` \| `1` \| `4` \| `auto` | `auto` | `4` en workstation (rescatar sesión gráfica colgada), `0` en server. |

### AppArmor (v2.1)

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `APPARMOR_EXTRA_PROFILES` | `1` \| `0` \| `auto` | `auto` → `1` | Despliega perfiles de `apparmor-profiles-extra` para binarios instalados. |
| `APPARMOR_EXTRA_MODE` | `complain` \| `enforce` | `complain` | Modo en que entran los perfiles extra recién desplegados. |
| `APPARMOR_ENFORCE_ALL` | `0` \| `1` | `0` | Promueve **todos** los perfiles en complain a enforce. Ver advertencias del PASO 11. |

### auditd (v2.1)

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `ENABLE_AUDITD` | `1` \| `0` | `1` | Instala y configura auditd. |
| `AUDIT_LEVEL` | `basic` \| `strict` | `basic` | `strict` añade accesos denegados, cambios de permisos, borrados y binarios privilegiados. Mucho más volumen. |
| `AUDIT_IMMUTABLE` | `0` \| `1` | `0` | `1` aplica `-e 2`: reglas inmutables hasta el siguiente reinicio. |

### Sandboxing (v2.1)

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `ENABLE_SANDBOX` | `1` \| `0` \| `auto` | `auto` → `1` en workstation | Activa el PASO 15 completo. |
| `INSTALL_FLATPAK` | `1` \| `0` \| `auto` | `auto` | `1` si hay sandbox **y** entorno gráfico detectado. |
| `INSTALL_FLATSEAL` | `1` \| `0` | `1` | Instala Flatseal. Descarga el runtime de GNOME (~700 MB) la primera vez. |
| `FLATPAK_LOCKDOWN` | `0` \| `1` | `0` | Aplica el recorte global de permisos Flatpak. Ver PASO 15. |
| `ENABLE_FIREJAIL` | `0` \| `1` | `0` | Instala firejail. Lee la advertencia antes. |

### ClamAV y AIDE

| Variable | Valores | Por defecto | Qué hace |
|---|---|---|---|
| `ENABLE_CLAMAV` | `1` \| `0` | `1` | Instala ClamAV y programa el escaneo semanal. |
| `CLAMAV_QUARANTINE` | `1` \| `0` \| `auto` | `auto` | `0` en workstation (solo informe), `1` en server (mueve lo detectado). |
| `ENABLE_AIDE` | `1` \| `0` | `1` | Instala AIDE y genera el baseline. |

---

## 6. Los 18 pasos, uno a uno

### PASO 1 — Estado inicial

Registra `uname -a`, la versión de Debian y las interfaces de red. No modifica nada. Sirve para que el log tenga contexto si algo va mal después.

---

### PASO 2 — Actualización completa

`apt-get update` seguido de `apt-get -y full-upgrade`.

Se hace **antes que nada** por una razón: aplicar hardening sobre un sistema sin parchear es maquillaje. La inmensa mayoría de los compromisos reales aprovechan vulnerabilidades con parche disponible.

`full-upgrade` (en vez de `upgrade`) permite instalar y eliminar paquetes si lo exige la resolución de dependencias. En una Debian estable esto es seguro; en testing/sid conviene revisarlo antes.

---

### PASO 3 — Herramientas base

Instala el conjunto de paquetes según las variables activas. Base fija:

```
sudo vim curl gnupg lsb-release ca-certificates
nftables fail2ban apparmor apparmor-utils
unattended-upgrades apt-listchanges
logwatch lynis mokutil
```

Condicionales: `openssh-server`, `aide aide-common`, `apparmor-profiles apparmor-profiles-extra`, `auditd audispd-plugins`, `bubblewrap`, `clamav clamav-freshclam` (+ `clamav-daemon` en server).

Los paquetes opcionales pasan por `pkg_exists()` antes de añadirse a la lista: si `apparmor-profiles-extra` o `audispd-plugins` no existieran en los repositorios configurados, el script avisa y sigue en lugar de abortar toda la instalación.

**Verificación:** `dpkg -l | grep -E 'apparmor-profiles|auditd|bubblewrap'`

---

### PASO 4 — Servicios innecesarios

En `server` desactiva `avahi-daemon`, `cups`, `cups-browsed`, `bluetooth`, `rpcbind` y `ModemManager`. En `workstation` solo `rpcbind`, y lo explica por pantalla.

`rpcbind` se desactiva en ambos: es el portmapper de NFS/NIS, escucha en el 111, y en un equipo que no sirve NFS no aporta nada.

**Verificación:** `systemctl is-enabled avahi-daemon cups bluetooth rpcbind`
**Reversión:** `sudo systemctl enable --now <servicio>`

---

### PASO 5 — Actualizaciones automáticas

Escribe dos ficheros:

- `/etc/apt/apt.conf.d/20auto-upgrades` — activa la comprobación y descarga periódicas.
- `/etc/apt/apt.conf.d/51blueshield-unattended` — comportamiento: limpia kernels y dependencias huérfanas, **no reinicia solo**, informa por correo a `root` cuando hay cambios.

`Automatic-Reboot "false"` es deliberado. Un reinicio automático a las 4 de la madrugada en un escritorio te hace perder trabajo abierto; en un servidor te tira un servicio sin ventana de mantenimiento. Lo que sí conviene es vigilar si hace falta reiniciar:

```bash
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required.pkgs
```

**Verificación:** `sudo unattended-upgrade --dry-run --debug`

---

### PASO 6 — Logs persistentes

Crea `/var/log/journal` y escribe `/etc/systemd/journald.conf.d/99-blueshield.conf`:

- `Storage=persistent` — los logs sobreviven al reinicio. Sin esto, un incidente nocturno se pierde al arrancar.
- `SystemMaxUse=1G`, `SystemMaxFileSize=128M`, `MaxRetentionSec=1month` — el tope evita que el journal se coma el disco, que es el efecto secundario clásico de activar la persistencia sin límite.
- `ForwardToSyslog=no` — si hay `rsyslog` instalado, evita duplicar cada línea en `/var/log/syslog`.

**Verificación:** `journalctl --disk-usage` y `journalctl --list-boots`

---

### PASO 7 — Hardening del kernel (sysctl)

Escribe `/etc/sysctl.d/99-blueshield.conf` y lo aplica con `sysctl --system`. Agrupado por bloques:

**Red IPv4.** `rp_filter` según perfil, `tcp_syncookies=1`, y desactivación de `accept_source_route`, `accept_redirects`, `secure_redirects` y `send_redirects` tanto en `all` como en `default`. `icmp_echo_ignore_broadcasts=1` (anti-Smurf), `icmp_ignore_bogus_error_responses=1`, `log_martians=1`.

**Red IPv6.** El mismo tratamiento de source-route y redirects. `accept_ra` se deja en `1`: apagarlo rompe la autoconfiguración en cualquier red doméstica con IPv6.

**Kernel.** `dmesg_restrict=1` y `kptr_restrict=2` (no filtrar direcciones del kernel a usuarios sin privilegios), `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `ldisc_autoload=0`, `sysrq` y `ptrace_scope` según variables, `perf_event_paranoid=2`.

**Sistema de archivos.** `protected_hardlinks`, `protected_symlinks`, `protected_fifos`, `protected_regular=2` y `suid_dumpable=0`. Este bloque mitiga toda una familia de ataques de carrera en directorios compartidos como `/tmp`.

**Verificación:**
```bash
sysctl -a --pattern 'kptr_restrict|rp_filter|protected_regular|ptrace_scope'
```

**Reversión:** `sudo rm /etc/sysctl.d/99-blueshield.conf && sudo sysctl --system`

---

### PASO 8 — SSH (si `ENABLE_SSH=1`)

Cuatro cosas importantes ocurren aquí:

**1. Configuración en drop-in.** Todo va a `/etc/ssh/sshd_config.d/99-blueshield.conf`, no al fichero principal. Debian coloca `Include /etc/ssh/sshd_config.d/*.conf` al principio de `sshd_config`, y en OpenSSH **gana el primer valor encontrado**. Editar el fichero principal significaría que un drop-in previo anule silenciosamente tus cambios. Si el `Include` faltara, el script lo añade.

**2. Guardia anti-lockout.** Antes de escribir `PasswordAuthentication no`, cuenta las claves no comentadas en `authorized_keys`. Si hay cero, aborta con instrucciones. Esta comprobación es la diferencia entre un script de hardening y una forma elegante de perder un servidor.

**3. Criptografía moderna.** Restringe `KexAlgorithms`, `Ciphers`, `MACs` y `HostKeyAlgorithms` a algoritmos actuales, incluido `sntrup761x25519-sha512` (intercambio de claves resistente a computación cuántica). Efecto secundario: clientes muy antiguos dejarán de conectar. Es intencionado.

**4. Validación antes de aplicar.** `sshd -t` valida la configuración; si falla, borra el drop-in y aborta **sin recargar el servicio**. Nunca te deja con un sshd que no arranca.

Otros ajustes: `PermitRootLogin no`, `AllowUsers` limitado al admin, `MaxAuthTries 3`, `LoginGraceTime 30`, `X11Forwarding no`, `AllowAgentForwarding no`, `PermitTunnel no`, `LogLevel VERBOSE` (necesario para que fail2ban vea los intentos).

**2FA opcional.** Con `ENABLE_SSH_2FA=1` instala `libpam-google-authenticator`, lo añade a `/etc/pam.d/sshd` y configura `AuthenticationMethods publickey,keyboard-interactive`. Ojo con el `nullok`: mientras esté, un usuario sin TOTP enrolado entra igual. Quítalo cuando todos estén enrolados o se queda como bypass permanente.

**Verificación:**
```bash
sudo sshd -T | grep -iE 'port|permitrootlogin|passwordauthentication|allowusers'
ssh -p 2222 usuario@host   # desde OTRA terminal, antes de cerrar la actual
```

---

### PASO 9 — Cortafuegos nftables

Crea `/etc/nftables.conf` con una tabla `inet blueshield` (una sola tabla para IPv4 e IPv6) y política **deny-by-default** en `input`.

Reglas, en orden:

1. `iif lo accept` — tráfico local.
2. `ct state established,related accept` — respuestas a conexiones salientes.
3. `ct state invalid drop` — descarta basura antes de evaluar nada más.
4. **ICMPv6 esencial sin límite de tasa**: `nd-neighbor-solicit`, `nd-neighbor-advert`, `nd-router-solicit`, `nd-router-advert`, `packet-too-big`, etc. Limitar estos rompe el descubrimiento de vecinos y la MTU en IPv6.
5. ICMPv6 echo e ICMPv4 útil, con límite de 10/s.
6. Cliente DHCP v4 y v6.
7. En workstation: mDNS (5353/udp) y SSDP (1900/udp).
8. Reglas de SSH y puertos extra, si aplican.
9. Registro de descartes limitado a 5/minuto.

**Reglas SSH por familia.** La función `add_ssh_rule()` mira si el CIDR contiene `:` y emite `ip6 saddr` o `ip saddr` en consecuencia. Emitir `ip6 saddr 192.168.1.0/24` haría que `nft` rechazara todo el fichero.

**Compatibilidad con Docker.** Si detecta Docker, **no** hace `flush ruleset` (que borraría las reglas que Docker inyecta vía `iptables-nft` y dejaría los contenedores sin red) sino que elimina y recrea solo su propia tabla. La cadena `forward` queda en `accept` porque Docker gestiona su propio filtrado. Sin Docker, `flush ruleset` y `forward` en `drop`.

**Validación antes de aplicar.** `nft -c -f` valida la sintaxis. Si falla, no aplica nada y conserva el fichero para inspección. Esto importa mucho: en la v1, un fichero inválido abortaba el script justo después de haber movido SSH de puerto — el peor momento posible.

**Verificación:**
```bash
sudo nft list table inet blueshield
sudo ss -tulpn                       # ¿qué escucha realmente?
journalctl -k -g 'blueshield-drop'     # qué se está descartando
```

---

### PASO 10 — fail2ban

Solo si SSH está activo; si no, lo desactiva (no hay servicio que proteger y el demonio solo sería consumo).

Escribe `/etc/fail2ban/jail.d/blueshield.local`:

- `backend = systemd` — lee del journal, no de un fichero. **`logpath` y `backend = systemd` son mutuamente excluyentes**: con backend systemd la ruta se ignora, y ese era el bug silencioso de la v1.
- `banaction = nftables[type=multiport]` — coherente con el cortafuegos. Con el banaction de iptables por defecto, los bloqueos no se aplicarían.
- `ignoreip` — incluye `127.0.0.1/8`, `::1` y **las redes locales detectadas automáticamente**, para que no te autobloquees desde tu propia LAN.
- 5 intentos en 10 minutos → 1 hora de bloqueo.

**Verificación:**
```bash
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip 192.168.1.50   # desbloquear a mano
```

---

### PASO 11 — AppArmor *(ampliado en v2.1)*

Cinco subfases.

**11.1 · ¿Es AppArmor un LSM activo?** Comprueba `/sys/kernel/security/lsm`. Si AppArmor no aparece ahí, el kernel arrancó sin él y todo lo demás sería decorativo: el script lo dice en rojo, sugiere revisar `/proc/cmdline` en busca de `apparmor=0` o `security=selinux`, y **salta el resto del paso**.

**11.2 · Despliegue de perfiles extra.** El paquete `apparmor-profiles-extra` deja sus perfiles en `/usr/share/apparmor/extra-profiles` **sin activarlos** — es un almacén, no una configuración. El script:

1. Recorre ese directorio.
2. Deriva el binario del nombre del perfil por la convención de AppArmor: `usr.bin.firefox` → `/usr/bin/firefox`.
3. Descarta el perfil si el binario no existe o no es ejecutable (no tiene sentido confinar lo que no está instalado).
4. Descarta el perfil si ya existe uno con ese nombre en `/etc/apparmor.d` (no se pisa nada).
5. **Valida con `apparmor_parser -Q`** (comprueba sintaxis sin cargar en el kernel). Un perfil que no valide se descarta con un aviso, en lugar de dejarte un `systemctl reload apparmor` roto en el siguiente arranque.
6. Copia con `cp -n` y lo pone en `complain` o `enforce` según `APPARMOR_EXTRA_MODE`.

**11.3 · Recarga.** `systemctl reload apparmor`, con `restart` como alternativa.

**11.4 · Promoción opcional a enforce.** Con `APPARMOR_ENFORCE_ALL=1`, obtiene la lista de perfiles en complain vía `aa-status --json` parseado con `python3` y les aplica `aa-enforce`. Respeta el modo elegido para los perfiles extra recién desplegados, para no contradecirse.

**11.5 · Informe.** Cuenta perfiles en enforce y complain, y ejecuta `aa-unconfined` para listar los procesos **en escucha que no están confinados**. Esa lista es tu trabajo pendiente real.

**Verificación:**
```bash
sudo aa-status
sudo aa-unconfined
journalctl -k -g 'apparmor="DENIED"' --since today
# Con auditd activo (PASO 12), las denegaciones se consultan así:
sudo ausearch -m AVC -i --start today
```

**El ciclo que hay que seguir después.** Los perfiles extra entran en `complain` por defecto: registran lo que habrían bloqueado, sin bloquear. Usa el equipo con normalidad una o dos semanas y luego:

```bash
sudo aa-logprof                                    # revisa y ajusta lo aprendido
sudo aa-enforce /etc/apparmor.d/usr.bin.firefox    # promueve los ya afinados
```

**Reversión:** `sudo aa-complain /etc/apparmor.d/<perfil>` para uno; `sudo rm /etc/apparmor.d/<perfil> && sudo systemctl reload apparmor` para quitarlo del todo.

---

### PASO 12 — auditd *(nuevo en v2.1)*

Escribe `/etc/audit/rules.d/99-blueshield.rules` y ajusta `/etc/audit/auditd.conf`.

**Control.** `-D` (limpia reglas previas), `-b 8192` (buffer), `--backlog_wait_time 60000`, y `-f 1`: registrar el fallo en `printk`. **Nunca `-f 2`**, que provoca kernel panic cuando el backlog se llena — un mecanismo de auditoría que tumba el equipo no es una mejora de seguridad.

**Nivel `basic`** (por defecto) vigila:

| Clave (`-k`) | Qué cubre |
|---|---|
| `identidad` | `/etc/passwd`, `shadow`, `group`, `gshadow` |
| `escalada` | `/etc/sudoers` y `sudoers.d/` |
| `autenticacion` | `/etc/pam.d/`, `/etc/security/` |
| `sesiones` | `lastlog`, `faillock` |
| `ssh` | `sshd_config` y `sshd_config.d/` |
| `kernel` | `sysctl.conf`, `sysctl.d/` |
| `modulos` | `modprobe.d/`, syscalls `init_module`/`finit_module`/`delete_module` |
| `arranque` | `/boot/` |
| `firewall`, `apparmor`, `auditoria`, `fail2ban`, `integridad` | Los ficheros de configuración de cada herramienta |
| `tiempo` | `adjtimex`, `settimeofday`, `clock_settime`, `/etc/localtime` |
| `programado` | `crontab`, `cron.d/`, `/etc/systemd/system/`, `/usr/local/sbin/` |
| `montaje` | `mount`/`umount2` de usuarios reales (auid ≥ 1000) |

**Nivel `strict`** añade accesos denegados (EACCES/EPERM), cambios de permisos y propietario, borrados y renombrados, y ejecución de `sudo`, `su`, `passwd`, `pkexec` y `crontab`. El propio fichero avisa: en un escritorio esto genera mucho volumen porque el navegador prueba rutas inexistentes sin parar.

**Arquitectura.** Las reglas se emiten con `arch=b64` o `arch=b32` según `getconf LONG_BIT`. Una regla `b64` en un sistema de 32 bits no carga y hace fallar todo el conjunto.

**Inmutabilidad.** Por defecto `-e 1` (activo, reglas modificables). Con `AUDIT_IMMUTABLE=1` pasa a `-e 2`: a prueba de manipulación, pero **cualquier cambio de reglas exige reiniciar el equipo**. En un servidor de producción tiene sentido; en un escritorio en el que aún estás afinando, es una molestia diaria.

**auditd.conf.** Tope de ~250 MB (`max_log_file 50`, `num_logs 5`, rotación) y, deliberadamente, **ninguna acción destructiva**: `space_left_action` y `admin_space_left_action` en `SYSLOG`, `disk_full_action` en `SUSPEND`. Nada de `SINGLE` ni `HALT`, que convertirían un disco lleno en una caída del equipo.

**Consulta:**
```bash
sudo ausearch -k escalada -i --start today    # cambios en sudoers
sudo ausearch -k identidad -i --start week
sudo ausearch -m AVC -i --start today         # denegaciones de AppArmor
sudo aureport --summary -i
sudo aureport --auth --summary -i
sudo auditctl -l | wc -l                      # reglas cargadas
sudo auditctl -s                              # estado, pérdidas, backlog
```

**Aviso importante:** con auditd en marcha, los mensajes de audit dejan de llegar a journald. Las denegaciones de AppArmor pasan de `journalctl -k` a `ausearch -m AVC`. No es un fallo, es cómo funciona el socket netlink de auditoría.

---

### PASO 13 — Secure Boot

Solo informa. `mokutil --sb-state` y, si está activo, recuerda que los módulos DKMS (NVIDIA, VirtualBox) necesitan firma e inscripción MOK o no cargarán. Relevante si vas a montar una GPU con driver propietario.

---

### PASO 14 — ClamAV *(unidad endurecida en v2.1)*

**Firmas.** Detiene `clamav-freshclam`, ejecuta `freshclam` a mano para la primera descarga (que puede tardar), y lo vuelve a activar.

**Script de escaneo** en `/usr/local/sbin/blueshield-clamscan`: recorre `/home /tmp /var/tmp /srv` con `nice -n 19 ionice -c3`, excluyendo `/proc`, `/sys`, `/dev`, `/run`, `.cache`, `.local/share/Trash`, `/var/lib/docker` y `/var/lib/flatpak`. Escribe en `/var/log/blueshield-clamscan.log`, con logrotate mensual y 6 rotaciones.

**Modo informe vs cuarentena.** Con `CLAMAV_QUARANTINE=0` (por defecto en escritorio) solo registra. Con `=1` añade `--move` al directorio de cuarentena. La razón del defecto está en el Anexo A.

**Unidad systemd confinada.** Es un `oneshot` que corre como root y recorre todo `/home`: exactamente el tipo de servicio que merece confinamiento.

| Directiva | Motivo |
|---|---|
| `NoNewPrivileges=yes` | No puede escalar vía setuid |
| `ProtectSystem=strict` | Todo el sistema de ficheros en solo lectura salvo lo declarado |
| `ProtectProc=invisible`, `ProcSubset=pid` | No ve los procesos de otros usuarios |
| `RestrictAddressFamilies=AF_UNIX` | Sin red: clamscan no la necesita (freshclam es otro servicio) |
| `MemoryDenyWriteExecute=yes` | W^X. ClamAV 1.x ya no usa el JIT de LLVM, así que no le afecta |
| `SystemCallFilter=@system-service` + denegaciones | Superficie de syscalls acotada |
| `PrivateTmp=no` | **A propósito**: el escaneo debe ver el `/tmp` real |
| `--tempdir=/var/lib/blueshield/tmp` | Consecuencia de lo anterior. Ver Anexo A |
| `CapabilityBoundingSet` variable | `CAP_DAC_READ_SEARCH` en informe; más `CAP_DAC_OVERRIDE` y `CAP_FOWNER` en cuarentena |
| `ProtectHome=read-only` (informe) | El servicio no puede escribir en `/home` |

Tras generarla, el script la valida con `systemd-analyze verify` y muestra la puntuación de `systemd-analyze security`.

**Verificación:**
```bash
sudo systemctl start blueshield-clamscan.service
sudo tail -f /var/log/blueshield-clamscan.log
systemd-analyze security blueshield-clamscan.service
systemctl list-timers blueshield-clamscan.timer
```

---

### PASO 15 — Sandboxing de aplicaciones *(nuevo en v2.1, opcional)*

Este paso ataca la superficie de ataque real de un escritorio: el navegador, el visor de PDF y el cliente de correo procesando ficheros de origen ajeno. Todo lo anterior protege el perímetro y la integridad del sistema; nada de lo anterior se interpone entre un PDF malicioso y tu `$HOME`.

**15.1 · `blueshield-sandbox`.** Envoltorio de bubblewrap en `/usr/local/bin/`. Ejecuta cualquier programa con:

- `$HOME` sobre un directorio temporal que se destruye al salir.
- Sin red por defecto (`--unshare-net`).
- Espacios de nombres separados de usuario, IPC, PID, UTS y cgroup.
- Todas las capacidades eliminadas (`--cap-drop ALL`).
- `/usr` y `/etc` en solo lectura; `/var`, `/tmp` y `/run` en tmpfs.
- Sockets gráficos (Wayland, X11), PipeWire y PulseAudio expuestos en solo lectura para que las apps con interfaz funcionen.

```bash
blueshield-sandbox --ro ~/Descargas/dudoso.pdf evince ~/Descargas/dudoso.pdf
blueshield-sandbox --net --dbus firefox
blueshield-sandbox --help
```

Opciones: `--net` (permite red), `--dbus` (expone el bus de sesión, que muchas apps GUI exigen), `--ro RUTA` y `--rw RUTA` (montar ficheros concretos).

**15.2 · Flatpak.** Instala `flatpak`, añade Flathub, instala el plugin del centro de software correspondiente (GNOME o Plasma) si detecta ese escritorio, y opcionalmente Flatseal.

**15.3 · `blueshield-flatpak-lockdown`.** Genera `/usr/local/sbin/blueshield-flatpak-lockdown` con el recorte global de permisos:

```
--nofilesystem=host     # sin acceso al sistema de ficheros del anfitrión
--nofilesystem=home     # sin acceso al home completo
--nosocket=x11          # X11 permite a cualquier cliente espiar el teclado ajeno
--socket=fallback-x11   # ...pero se usa X11 si no hay Wayland
--socket=wayland
--nodevice=all --device=dri   # sin dispositivos, conservando la GPU
```

**El script NO lo ejecuta solo** salvo que pases `FLATPAK_LOCKDOWN=1`. Es un cambio que puede hacer que LibreOffice deje de ver tus documentos hasta que le des acceso concreto, y esa es una decisión tuya, no del script. Las aplicaciones seguirán abriendo ficheros a través de los portales XDG (el diálogo "Abrir" del escritorio), que conceden acceso fichero a fichero.

Revertir: `flatpak override --reset`. Ver lo aplicado: `flatpak override --show`.

**15.4 · firejail.** Solo con `ENABLE_FIREJAIL=1`, y con advertencia explícita: se instala con SUID root e históricamente ha acumulado CVEs de escalada local. Es una herramienta de aislamiento cuyo propio binario amplía la superficie de ataque. Bubblewrap y Flatpak cubren lo mismo sin ese riesgo.

---

### PASO 16 — AIDE

**Va al final a propósito.** El baseline de integridad debe reflejar el estado **definitivo** del sistema. En la v1 se ejecutaba antes de instalar ClamAV, con lo que el primer informe diario ya salía lleno de diferencias y el usuario aprendía a ignorarlo — que es la peor manera de tener un sistema de detección.

Escribe exclusiones en `/etc/aide/aide.conf.d/99-blueshield`: `/home`, `/var/log`, `/var/cache`, `/tmp`, `/var/tmp`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/clamav`, `/var/log/audit`, `/var/lib/flatpak`, `/var/lib/aide`, `/var/lib/systemd`, `/root/blueshield-backups` y `/srv/datos`.

En escritorio, `/home` cambia constantemente: sin excluirlo, los informes diarios son ilegibles. **Ajusta esta lista a tus montajes de datos reales.**

Después ejecuta `aideinit` y copia `aide.db.new` a `aide.db`.

**Verificación:** `sudo aide --check --config /etc/aide/aide.conf`

**Complementariedad con auditd:** AIDE te dice **qué** cambió. auditd te dice **cuándo y quién**. Juntos son una investigación; por separado, dos preguntas a medias.

---

### PASO 17 — Auditoría Lynis

`lynis audit system --quick --quiet` y extrae el índice de endurecimiento del log. Es una métrica orientativa, no un objetivo: perseguir el 100 lleva a aplicar recomendaciones que no encajan con tu caso de uso.

```bash
grep -E '^\s*(\*|-) ' /var/log/lynis-report.dat   # sugerencias
sudo less /var/log/lynis.log                       # informe completo
```

---

### PASO 18 — Resumen

Imprime la configuración final, servicios en escucha (`ss -tulpn`), la cadena `input` de nftables, el estado de fail2ban, los recordatorios pendientes (probar SSH, enrolar TOTP, ciclo de AppArmor) y la lista de lo que queda fuera de alcance.

---

## 7. Ficheros y unidades que toca

### Ficheros creados o modificados

| Ruta | Paso | ¿Backup? |
|---|---|---|
| `/root/blueshield-backups/<fecha>/` | — | Es el propio backup |
| `/etc/apt/apt.conf.d/20auto-upgrades` | 5 | No (se sobrescribe) |
| `/etc/apt/apt.conf.d/51blueshield-unattended` | 5 | No (fichero nuevo) |
| `/etc/systemd/journald.conf.d/99-blueshield.conf` | 6 | Sí (`journald.conf.bak`) |
| `/etc/sysctl.d/99-blueshield.conf` | 7 | Sí |
| `/etc/ssh/sshd_config` | 8 | Sí (solo si falta el `Include`) |
| `/etc/ssh/sshd_config.d/99-blueshield.conf` | 8 | Sí |
| `~<admin>/.ssh/authorized_keys` | 8 | No (solo añade) |
| `/etc/pam.d/sshd` | 8 | Sí (solo con 2FA) |
| `/etc/nftables.conf` | 9 | Sí |
| `/etc/fail2ban/jail.d/blueshield.local` | 10 | No (fichero nuevo) |
| `/etc/apparmor.d/<perfiles>` | 11 | No (`cp -n`, no pisa nada) |
| `/etc/audit/rules.d/99-blueshield.rules` | 12 | Sí |
| `/etc/audit/auditd.conf` | 12 | Sí |
| `/usr/local/sbin/blueshield-clamscan` | 14 | No |
| `/etc/systemd/system/blueshield-clamscan.{service,timer}` | 14 | No |
| `/etc/logrotate.d/blueshield-clamscan` | 14 | No |
| `/var/lib/blueshield/{cuarentena,tmp}/` | 14 | — |
| `/usr/local/bin/blueshield-sandbox` | 15 | No |
| `/usr/local/sbin/blueshield-flatpak-lockdown` | 15 | No |
| `/etc/aide/aide.conf.d/99-blueshield` | 16 | No (fichero nuevo) |
| `/var/lib/aide/aide.db` | 16 | No |

> **Nota honesta:** el script respalda los ficheros que *modifica*, no los que *crea*. Para los ficheros nuevos, la reversión es borrarlos (sección 12).

### Unidades systemd

| Unidad | Estado | Paso |
|---|---|---|
| `nftables.service` | activada | 9 |
| `fail2ban.service` | activada si hay SSH | 10 |
| `apparmor.service` | activada | 11 |
| `auditd.service` | activada | 12 |
| `clamav-freshclam.service` | activada | 14 |
| `blueshield-clamscan.timer` | activada (domingos 03:00, con retardo aleatorio de 0–30 min) | 14 |
| `blueshield-clamscan.service` | oneshot, disparada por el timer | 14 |

---

## 8. Herramientas que instala

### `blueshield-sandbox`

```
blueshield-sandbox [--net] [--dbus] [--ro RUTA] [--rw RUTA] COMANDO [ARGS...]
```

Ejecuta un programa en un contenedor bubblewrap desechable. Sin red y sin bus de sesión por defecto; `$HOME` es temporal y se destruye al salir.

**Limitación honesta:** bubblewrap aísla mediante espacios de nombres del kernel. Un 0-day del kernel sigue siendo un 0-day del kernel. Es una reducción de riesgo real, no una máquina virtual.

### `blueshield-flatpak-lockdown`

Aplica el recorte global de permisos Flatpak. Requiere root. No se ejecuta automáticamente salvo `FLATPAK_LOCKDOWN=1`.

### `blueshield-clamscan`

Script de escaneo invocado por el timer semanal. Se puede lanzar a mano, pero conviene hacerlo vía `systemctl start blueshield-clamscan.service` para que corra con el confinamiento de la unidad.

---

## 9. Verificación posterior

Lista de comprobación tras la primera ejecución:

```bash
# ── Cortafuegos ──
sudo nft list table inet blueshield
sudo ss -tulpn                    # ¿escucha algo que no esperas?

# ── SSH (si aplica) ──
sudo sshd -T | grep -iE 'port|passwordauth|permitroot|allowusers'
ssh -p 2222 usuario@host          # DESDE OTRA TERMINAL

# ── AppArmor ──
sudo aa-status
sudo aa-unconfined
sudo ausearch -m AVC -i --start today

# ── auditd ──
sudo auditctl -s                  # ¿enabled 1? ¿lost 0?
sudo auditctl -l | wc -l
sudo aureport --summary -i

# ── ClamAV ──
systemctl list-timers blueshield-clamscan.timer
systemd-analyze security blueshield-clamscan.service

# ── AIDE ──
sudo aide --check --config /etc/aide/aide.conf

# ── Kernel ──
sysctl -a --pattern 'kptr_restrict|rp_filter|ptrace_scope|protected_regular'

# ── Actualizaciones ──
sudo unattended-upgrade --dry-run --debug
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required.pkgs
```

---

## 10. Operación diaria

**Semanal (5 minutos):**

```bash
sudo aide --check --config /etc/aide/aide.conf | head -40
sudo aureport --summary -i
sudo fail2ban-client status sshd
tail -30 /var/log/blueshield-clamscan.log
```

**Tras cualquier cambio de configuración del sistema**, actualiza el baseline de AIDE o los informes se llenarán de ruido:

```bash
sudo aideinit -y -f
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**Durante las primeras semanas**, el ciclo de AppArmor:

```bash
sudo aa-logprof
sudo aa-enforce /etc/apparmor.d/<perfil afinado>
```

**Cuando cambien tus necesidades**, relanza el script con las variables nuevas en lugar de editar los ficheros a mano. Así la configuración sigue siendo reproducible:

```bash
sudo ALLOW_HTTPS=1 EXTRA_TCP_PORTS="8006" ./blueshield-debian13_v2.1.sh
```

---

## 11. Resolución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| El script aborta con "No se pudo determinar un usuario administrador" | No hay `$SUDO_USER` ni usuarios con UID ≥ 1000 | `sudo ADMIN_USER=tuusuario ./blueshield...` |
| Aborta en el PASO 8 por falta de claves | `authorized_keys` vacío | `ssh-copy-id` primero, o `PUBKEY="ssh-ed25519 ..."` |
| Los contenedores Docker pierden la red | `DOCKER_COMPAT` se resolvió a 0 | Relanza con `DOCKER_COMPAT=1` |
| No resuelve nombres `.local` ni ve la impresora | Perfil `server` en un escritorio | Relanza con `PROFILE=workstation` |
| Una app deja de abrir ficheros tras el PASO 11 | Perfil AppArmor en enforce demasiado estricto | `sudo ausearch -m AVC -i` para ver qué; luego `aa-complain <perfil>` |
| `/var/log/audit` crece sin control | `AUDIT_LEVEL=strict` en un escritorio | Relanza con `AUDIT_LEVEL=basic` |
| No puedo cambiar las reglas de auditoría | `-e 2` activo | Reinicia el equipo; luego `AUDIT_IMMUTABLE=0` |
| Las denegaciones de AppArmor no salen en `journalctl` | auditd captura el socket netlink | Usa `sudo ausearch -m AVC -i` |
| El escaneo de ClamAV falla con archivos comprimidos | `--tempdir` no escribible | Comprueba que `/var/lib/blueshield/tmp` existe y está en `ReadWritePaths` |
| El escaneo falla con SIGSEGV | `MemoryDenyWriteExecute` con una versión de ClamAV con JIT | Comenta esa línea en la unidad y `daemon-reload` |
| LibreOffice no ve mis documentos tras el lockdown de Flatpak | Recorte global aplicado | `flatpak override org.libreoffice.LibreOffice --filesystem=~/Documentos` |
| VPN: se pierden paquetes | `rp_filter=1` con rutas asimétricas | `RP_FILTER=2` |
| `gdb -p PID` no funciona | `ptrace_scope=1` | `PTRACE_SCOPE=0`, o depura solo procesos hijos |
| Un módulo DKMS no carga | Secure Boot activo sin firma MOK | Firma el módulo e inscribe la clave con `mokutil` |

**Dónde mirar siempre primero:** `/root/blueshield-backups/<última fecha>/blueshield.log`. Contiene la salida completa de todos los comandos, incluidos los que fallaron.

---

## 12. Reversión

### Deshacer un bloque concreto

```bash
# sysctl
sudo rm /etc/sysctl.d/99-blueshield.conf && sudo sysctl --system

# nftables
sudo rm /etc/nftables.conf && sudo systemctl stop nftables && sudo nft flush ruleset

# SSH
sudo rm /etc/ssh/sshd_config.d/99-blueshield.conf && sudo systemctl reload ssh

# fail2ban
sudo rm /etc/fail2ban/jail.d/blueshield.local && sudo systemctl restart fail2ban

# auditd
sudo rm /etc/audit/rules.d/99-blueshield.rules && sudo augenrules --load
sudo cp /root/blueshield-backups/<fecha>/auditd.conf.bak /etc/audit/auditd.conf

# AppArmor (un perfil)
sudo aa-complain /etc/apparmor.d/usr.bin.firefox
# AppArmor (quitarlo del todo)
sudo rm /etc/apparmor.d/usr.bin.firefox && sudo systemctl reload apparmor

# ClamAV programado
sudo systemctl disable --now blueshield-clamscan.timer
sudo rm /etc/systemd/system/blueshield-clamscan.{service,timer} && sudo systemctl daemon-reload

# journald
sudo rm /etc/systemd/journald.conf.d/99-blueshield.conf && sudo systemctl restart systemd-journald

# Flatpak lockdown
sudo flatpak override --reset
```

### Restaurar desde backup

```bash
ls /root/blueshield-backups/
sudo cp /root/blueshield-backups/2026-09-03-181500/sshd_config.bak /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
```

Valida siempre antes de recargar el servicio.

---

## Anexo A — Decisiones de diseño

Este anexo recoge el razonamiento de las decisiones que a primera vista parecen equivocadas o subóptimas. En casi todos los casos, la alternativa "más segura" rompe algo o da una falsa sensación de protección.

### A.1 · Por qué AppArmor y no SELinux

Debian activa AppArmor por defecto desde Debian 10 y toda la integración de la distribución está construida sobre él. SELinux existe en Debian (`selinux-basics`, `selinux-policy-default`, refpolicy 2.20250213 en trixie) pero es un ciudadano de segunda: la política de referencia está orientada a servidor, y en un escritorio GNOME/KDE la mayor parte del entorno gráfico —portales XDG, PipeWire, Flatpak, sesiones de usuario de systemd— queda en `unconfined_t`. El resultado es un coste de fricción alto (etiquetado, `restorecon`, `audit2allow` para cada binario de terceros) a cambio de una ganancia real cercana a cero justo donde está tu riesgo. Además, solo puede haber un LSM mayor activo: adoptar SELinux significa apagar los perfiles de AppArmor que hoy sí protegen.

Si el objetivo es aprender SELinux —cosa razonable si tocas RHEL o certificaciones— el sitio para hacerlo es una VM del laboratorio, no la máquina de trabajo diaria.

### A.2 · Por qué los perfiles extra entran en `complain` y no en `enforce`

Un perfil de AppArmor recién desplegado no conoce tu instalación concreta: dónde tienes los documentos, qué extensiones usa tu navegador, en qué ruta está tu impresora de red. Ponerlo en `enforce` de entrada produce fallos silenciosos que aparecen días después y en el peor momento.

En `complain` el perfil registra todo lo que habría bloqueado sin bloquear nada. Tras una o dos semanas de uso normal, `aa-logprof` te enseña esos registros y te deja ajustar el perfil a tu realidad. Solo entonces `aa-enforce` tiene sentido.

Dicho de otro modo: `complain` no es una versión débil de `enforce`, es la fase de aprendizaje obligatoria antes de él. Saltársela produce perfiles que o bien se acaban desactivando por molestos, o bien se ensanchan con `audit2allow`-equivalentes hasta no proteger de nada.

### A.3 · Por qué se valida cada perfil con `apparmor_parser -Q` antes de copiarlo

`apparmor-profiles-extra` es un almacén de perfiles de calidad variable, algunos escritos contra versiones antiguas del parser o que referencian abstracciones que ya no existen. Copiar uno inválido a `/etc/apparmor.d` no rompe nada de inmediato, pero **el siguiente arranque falla al cargar el conjunto**, dejándote sin ninguno de los perfiles.

`-Q` (`--skip-kernel-load`) valida la sintaxis sin cargar nada. Un perfil que no pasa se descarta con un aviso. Es una comprobación barata que evita un fallo diferido y difícil de diagnosticar.

### A.4 · Por qué la heurística nombre→binario

AppArmor nombra sus perfiles sustituyendo `/` por `.`: `/usr/bin/firefox` → `usr.bin.firefox`. El script invierte esa transformación para saber a qué binario apunta cada perfil y solo despliega los de binarios realmente instalados.

Es una heurística, no una garantía —un binario con un punto en el nombre la rompería— pero como solo se copia el perfil cuando la ruta resultante existe **y es ejecutable**, un fallo de la heurística produce una omisión, nunca un despliegue equivocado. Fallar hacia el lado seguro.

### A.5 · Por qué `tcp_timestamps = 1`

Es habitual ver `net.ipv4.tcp_timestamps = 0` en guías de hardening, con el argumento de que las marcas de tiempo revelan el uptime de la máquina. Dos motivos para no hacerlo:

1. Desde Linux 4.10 el offset de las marcas se aleatoriza por conexión, así que el uptime ya no se deduce de ahí. El beneficio anti-fingerprinting es despreciable.
2. Desactivarlas apaga PAWS (protección contra números de secuencia envueltos) y degrada la estimación de RTT, lo que empeora el rendimiento en enlaces rápidos o con latencia variable.

Se paga un coste real de red por un beneficio de seguridad que ya no existe.

### A.6 · Por qué `rp_filter = 2` en escritorio

El filtrado de ruta inversa estricto (`1`) descarta paquetes cuya ruta de vuelta no coincide con la interfaz de entrada. Es correcto en un servidor con topología estable. En un portátil con VPN, contenedores, o dos interfaces activas (cable y Wi-Fi), las rutas asimétricas son normales y `1` produce descartes intermitentes que se diagnostican fatal. El modo laxo (`2`) sigue descartando lo que no tiene ninguna ruta de vuelta, que es el 90 % del beneficio.

### A.7 · Por qué ICMPv6 esencial va sin límite de tasa

En IPv6, el descubrimiento de vecinos (ND) y los anuncios de router (RA) son ICMPv6. Limitar todo el ICMPv6 a 10 paquetes por segundo —como hacía la v1— rompe la resolución de direcciones y la autoconfiguración en cuanto hay algo de actividad en la red. `packet-too-big` es peor todavía: sin él se rompe el descubrimiento de MTU y las conexiones se cuelgan a medias.

Por eso hay dos conjuntos: los tipos esenciales se aceptan sin límite, y solo `echo-request` se limita.

### A.8 · Por qué la tabla propia en lugar de `flush ruleset` con Docker

Docker inyecta sus reglas de NAT y forward vía `iptables-nft`, que comparte el motor con nftables. Un `flush ruleset` las borra todas y deja los contenedores sin red, con la particularidad de que Docker no las reinstala hasta que se reinicia el demonio. El síntoma —"los contenedores dejaron de tener red después de reiniciar"— es difícil de relacionar con el cortafuegos.

La alternativa es una tabla propia (`inet blueshield`) que se elimina y recrea sin tocar nada más, y una cadena `forward` en `accept` porque el filtrado de contenedores lo gestiona Docker. A cambio se pierde el control del reenvío: si desinstalas Docker, hay que relanzar con `DOCKER_COMPAT=0`.

### A.9 · Por qué la configuración de SSH va en un drop-in

Debian coloca `Include /etc/ssh/sshd_config.d/*.conf` **al principio** de `sshd_config`. En OpenSSH, para la mayoría de directivas gana el **primer** valor encontrado. Consecuencia: cualquier cosa que edites en el fichero principal puede quedar anulada por un drop-in que ni sabías que existía, sin ningún mensaje de error.

Escribir en `99-blueshield.conf` garantiza que la configuración tiene efecto, y el nombre con prefijo numérico alto la sitúa después de otros drop-ins en el orden alfabético (aunque, por la regla del primer valor, lo que importa es que esté dentro del `Include`).

### A.10 · Por qué el guardia anti-lockout no es opcional

`PasswordAuthentication no` sin una clave válida instalada es la forma más común de perder acceso a un servidor remoto. El script cuenta las líneas no comentadas de `authorized_keys` y aborta si son cero, con instrucciones concretas. También hace una pausa después de aplicar los cambios y obliga a probar la conexión desde otra terminal.

Un script de hardening que puede dejarte fuera de tu propia máquina no es una herramienta de seguridad, es un riesgo operativo.

### A.11 · Por qué `-f 1` y nunca `-f 2` en auditd

`-f 2` hace que el kernel entre en pánico cuando el backlog de auditoría se llena. La lógica es "prefiero que el sistema caiga antes que perder un registro de auditoría", válida en entornos de altísima seguridad con requisitos formales de no repudio.

En un escritorio o un servidor normal significa que un pico de actividad —una compilación, un `rsync` grande, `AUDIT_LEVEL=strict` con el navegador abierto— tumba el equipo. `-f 1` registra el fallo en `printk` y sigue. Un mecanismo de auditoría que provoca caídas acaba desactivado, y entonces no auditas nada.

Por la misma lógica, `admin_space_left_action` se fija en `SYSLOG` y no en `SINGLE`: un disco lleno no debe dejarte en modo monousuario.

### A.12 · Por qué `-e 1` por defecto y no `-e 2`

`-e 2` hace las reglas inmutables hasta el siguiente reinicio: un atacante con root no puede desactivar la auditoría sin reiniciar, lo cual deja rastro. Es la configuración correcta para un servidor de producción estable.

En un equipo donde todavía estás afinando qué auditar, significa que cada ajuste de reglas cuesta un reinicio. La mayoría de la gente que lo activa sin entenderlo acaba desactivando auditd entero por frustración. Por eso es opt-in vía `AUDIT_IMMUTABLE=1`.

### A.13 · Por qué `basic` y `strict` en lugar de un único conjunto de reglas

Las reglas de auditoría "completas" que circulan por Internet (derivadas de las guías CIS y STIG) están pensadas para servidores. Aplicadas a un escritorio, las reglas de accesos denegados generan decenas de miles de eventos al día: el navegador prueba rutas inexistentes constantemente, y cada `open()` con EACCES es un registro.

El resultado práctico es que `/var/log/audit` crece sin control y nadie vuelve a leer un informe. `basic` cubre lo que de verdad quieres saber —quién tocó sudoers, quién cargó un módulo, quién cambió la hora— con un volumen que se puede revisar de verdad.

### A.14 · Por qué `PrivateTmp=no` y `--tempdir` en la unidad de ClamAV

Dos requisitos que chocan:

- El escaneo tiene que **ver el `/tmp` real**, porque `/tmp` es una de las rutas que escanea. `PrivateTmp=yes` le daría un `/tmp` vacío y el escaneo sería inútil.
- Pero `ProtectSystem=strict` deja todo el sistema de ficheros en solo lectura salvo lo declarado en `ReadWritePaths`, y clamscan **necesita escribir** al desempaquetar archivos comprimidos (un `.zip`, un `.docx`, un `.tar.gz`), porque su directorio temporal por defecto es `/tmp`.

Sin resolver esto, el escaneo de cualquier fichero comprimido falla —y falla de forma poco visible, dentro del log semanal. La solución es `--tempdir=/var/lib/blueshield/tmp`, un directorio propio declarado en `ReadWritePaths`, que mantiene `/tmp` en solo lectura para el servicio sin perder la capacidad de escanear archivos.

### A.15 · Por qué no se bloquea `@resources` en el filtro de syscalls

El conjunto `@resources` de systemd incluye `setpriority` e `ioprio_set`, que son exactamente las llamadas que hace el `nice -n 19 ionice -c3` del script de escaneo. Bloquearlas haría que el escaneo abortase o corriese a prioridad normal, penalizando el equipo durante una hora los domingos.

Es un ejemplo de una regla general: **un filtro que rompe el servicio no es hardening, es una avería con buena intención**. Se bloquean `@privileged`, `@mount`, `@debug`, `@swap`, `@reboot` y `@clock`, que clamscan no necesita para nada.

### A.16 · Por qué las capacidades cambian según el modo de cuarentena

En modo informe, el servicio solo necesita leer: `CAP_DAC_READ_SEARCH` basta para recorrer `/home` completo aunque los ficheros sean de otro usuario.

En modo cuarentena tiene que **mover** los ficheros detectados, lo que implica borrarlos de su directorio original. Escribir en un directorio propiedad de otro usuario requiere `CAP_DAC_OVERRIDE`, y modificar metadatos requiere `CAP_FOWNER`. Dárselas siempre sería conceder permisos que en el 90 % de los casos no se usan; no dárselas nunca haría que la cuarentena fallara en silencio.

### A.17 · Por qué la cuarentena está desactivada por defecto en escritorio

`clamscan --move` sobre `/home` significa que un falso positivo te quita un fichero de trabajo sin avisar. ClamAV tiene una tasa de falsos positivos no despreciable, especialmente con ficheros comprimidos, instaladores y binarios poco comunes.

En un servidor de correo o un recurso Samba, mover automáticamente es lo correcto: el fichero está en tránsito y el coste de aislarlo es bajo. En tu carpeta de documentos, el coste es perder trabajo y no enterarte hasta semanas después. El modo informe registra la detección y te deja decidir.

### A.18 · Por qué el lockdown de Flatpak no se aplica automáticamente

`--nofilesystem=home` es exactamente el tipo de cambio que hace que LibreOffice deje de ver tus documentos y que el usuario, sin saber por qué, desinstale toda la configuración de seguridad. La ganancia es real, pero requiere entender que a partir de ese momento los ficheros se abren por los portales XDG (el diálogo "Abrir" del escritorio) y no por acceso directo.

El script genera el mecanismo, lo documenta y lo deja preparado. Aplicarlo es una decisión informada, no un efecto secundario de ejecutar un script de hardening. Con `FLATPAK_LOCKDOWN=1` lo aplica, y en ese caso te dice cómo revertirlo.

### A.19 · Por qué firejail no está activado por defecto

Firejail se instala con SUID root y ha acumulado varias CVEs de escalada local a lo largo de los años. Es una herramienta cuyo propósito es aislar procesos, pero cuyo propio binario privilegiado amplía la superficie de ataque del sistema.

Bubblewrap (que no necesita SUID en kernels con espacios de nombres de usuario sin privilegios) y Flatpak (que usa bubblewrap por debajo) cubren el mismo caso de uso sin ese compromiso. Si aun así lo quieres, `ENABLE_FIREJAIL=1` lo instala y te sugiere quitarle el SUID con `dpkg-statoverride` si no necesitas sus funciones de red.

### A.20 · Por qué AIDE va al final

El baseline de integridad debe reflejar el estado definitivo del sistema. Generarlo antes de instalar el resto de paquetes produce un primer informe lleno de diferencias legítimas.

Eso tiene un efecto peor que el ruido: enseña al usuario a ignorar los informes de AIDE. Un sistema de detección de intrusiones que se ignora es peor que no tenerlo, porque da una falsa sensación de cobertura.

### A.21 · Por qué avahi, cups y bluetooth se conservan en escritorio

La v1 los desactivaba en todos los perfiles, siguiendo guías de hardening de servidor. En un escritorio eso significa perder la impresión, el descubrimiento de escáneres, la resolución de nombres `.local` y los periféricos inalámbricos.

El cálculo es simple: son servicios que escuchan en la red local, sí, pero el coste diario de apagarlos es alto y constante, mientras que el riesgo que eliminan es bajo en una red doméstica ya protegida por el cortafuegos. Un hardening que hace el equipo inutilizable se acaba revirtiendo entero, y entonces se pierde también todo lo que sí valía la pena.

### A.22 · Por qué `ptrace_scope = 1` y no `3`

`ptrace_scope=3` desactiva `ptrace` por completo y no se puede volver a bajar sin reiniciar. Rompe `gdb`, `strace`, los depuradores de los IDE y varios instaladores. `ptrace_scope=1` impide adjuntarse a procesos ajenos —que es el vector real, robar credenciales de un proceso en ejecución— pero deja depurar procesos hijos propios, que es lo que se hace el 99 % de las veces.

### A.23 · Por qué `ForwardToSyslog=no`

Si hay `rsyslog` instalado (viene en muchas instalaciones), cada línea del journal se duplica en `/var/log/syslog`. Con logs persistentes y un tope de 1 GB en el journal, eso significa hasta 2 GB de los mismos datos. Desactivar el reenvío no pierde nada mientras uses `journalctl`.

### A.24 · Por qué no hay reinicio automático de `unattended-upgrades`

En un escritorio, un reinicio a las 4 de la madrugada te hace perder documentos abiertos y sesiones. En un servidor, te tira un servicio sin ventana de mantenimiento y sin nadie mirando.

La alternativa es responsabilidad del operador: comprobar `/var/run/reboot-required` y reiniciar cuando convenga. El script lo deja explícito en el PASO 5.

---

## Anexo B — Historial de versiones y bugs corregidos

### v1 → v2.0

**Bugs que abortaban la ejecución:**

| Bug | Efecto |
|---|---|
| `ADMIN_USER` nunca se definía | `unbound variable` con `set -u`, aborto inmediato |
| `require_root` iba después del `mkdir` de `BACKUP_DIR` | Error confuso en lugar del mensaje claro |
| `ip6 saddr 192.168.1.0/24` con CIDR IPv4 | `nft` rechazaba el fichero, abortando **justo después de mover SSH de puerto** |
| `systemctl status \| head` sin `\|\| true` | Aborto por código de salida y posible SIGPIPE bajo `set -euo pipefail` |

**Bugs silenciosos (peores, porque no avisan):**

| Bug | Efecto |
|---|---|
| `PUBKEY` declarado y nunca usado | La clave no se instalaba; combinado con `PasswordAuthentication no`, lockout |
| Configuración SSH en el fichero principal | Anulada silenciosamente por el `Include` de Debian |
| 2FA con `KbdInteractiveAuthentication` desactivado | El TOTP nunca funcionaba |
| `ChallengeResponseAuthentication` | Obsoleto desde OpenSSH 8.7 |
| `flush ruleset` con Docker instalado | Contenedores sin red tras reiniciar |
| fail2ban con `logpath` **y** `backend = systemd` | Mutuamente excluyentes: la ruta se ignoraba |
| fail2ban sin `banaction` para nftables | Los bloqueos no se aplicaban |
| ICMPv6 limitado a 10/s en bloque | ND y RA rotos, IPv6 inestable |
| Sin cobertura IPv6 en sysctl | La mitad del hardening de red no aplicaba |
| Directorio de cuarentena creado y nunca usado | Falsa sensación de que había escaneo con aislamiento |
| AIDE inicializado antes de instalar ClamAV | Primer informe diario lleno de diferencias |
| avahi/cups/bluetooth desactivados en escritorio | Sin impresión, sin `.local`, sin periféricos |

**Mejoras funcionales:** perfiles `workstation`/`server`, algoritmos criptográficos modernos en SSH, guardia anti-lockout, validación previa (`sshd -t`, `nft -c`), y comentarios explicando cada decisión en los ficheros generados.

### v2.0 → v2.1

**Los cuatro añadidos:**

1. **PASO 11 ampliado.** La v2.0 solo contaba perfiles con `aa-status`. Ahora verifica el LSM activo, instala `apparmor-profiles(-extra)`, valida y despliega perfiles para los binarios instalados, gestiona modos complain/enforce y lista procesos sin confinar.
2. **PASO 12 nuevo: auditd.** No existía en absoluto. `logwatch` y `lynis` son informes y auditoría puntual, no traza de syscalls.
3. **Unidad de ClamAV endurecida.** En la v2.0 llevaba solo `Nice=19` e `IOSchedulingClass=idle`, siendo un `oneshot` root que recorre `/home` con permiso de mover ficheros.
4. **PASO 15 nuevo: sandboxing.** No había nada entre un PDF malicioso y `$HOME`, siendo esa la superficie de ataque real de un escritorio.

**Correcciones y ajustes menores:**

| Cambio | Motivo |
|---|---|
| `CLAMAV_QUARANTINE=0` por defecto en escritorio | Un falso positivo no debe llevarse un fichero de trabajo |
| `KERNEL_SYSRQ` como variable | Era un `4` heredado sin decisión consciente |
| `--tempdir` en clamscan | `ProtectSystem=strict` deja `/tmp` en solo lectura |
| `@resources` fuera del filtro de syscalls | Contiene `setpriority`/`ioprio_set`, usados por `nice`/`ionice` |
| Capacidades según modo de cuarentena | `CAP_DAC_OVERRIDE`/`CAP_FOWNER` solo cuando hacen falta |
| `logrotate` para el log de escaneo | Crecía sin límite |
| `AA_COPIED` declarado antes del paso | `${#array[@]:-0}` es sintaxis inválida en bash con `set -u` |
| Rango de `sed` en la ayuda de `blueshield-sandbox` | Imprimía tres líneas de más |
| Exclusiones de AIDE ampliadas | `/var/log/audit` y `/var/lib/flatpak` generaban ruido diario |

**Verificación de la v2.1:** `bash -n` y `shellcheck -S warning` sin avisos sobre el script principal y sobre los tres scripts embebidos por separado; generación simulada de las reglas de auditoría (niveles `basic` y `strict`) y de las dos variantes de la unidad systemd.

---

## Anexo C — Fuera de alcance

Cosas que este script **no** hace, con indicación de dónde resolverlas.

| Tema | Por qué queda fuera | Dónde se resuelve |
|---|---|---|
| **Cifrado de disco (LUKS)** | Se decide en el instalador; no se puede aplicar a posteriori sin reinstalar o migrar | Instalador de Debian, opción "cifrado LVM" |
| **Contraseña de GRUB** | Requiere decisiones sobre el flujo de arranque desatendido | `grub-mkpasswd-pbkdf2` + `/etc/grub.d/40_custom` |
| **`nodev,nosuid,noexec` en `/tmp` y `/var/tmp`** | Depende del esquema de particionado, que varía | `/etc/fstab` o unidades `.mount` de systemd |
| **usbguard** | Necesita una política de dispositivos que solo tú puedes definir | `usbguard generate-policy` tras conectar tus periféricos habituales |
| **Envío de logs a un SIEM** | Depende de tu colector | `audispd-plugins` (ya instalado) con `au-remote`, o el agente de tu SIEM |
| **Copias de seguridad** | Es un problema distinto, y más importante que casi todo lo de aquí | Borg, restic, o el mecanismo que ya uses |
| **Firmado de módulos DKMS** | Interactivo por naturaleza (inscripción MOK) | `mokutil --import` tras firmar |
| **Endurecimiento de aplicaciones concretas** | Fuera del alcance de una línea base | Perfiles de AppArmor propios, drop-ins de systemd |

---

*Documento generado para acompañar a `blueshield-debian13_v2.1.sh`. Si modificas el script, actualiza la tabla de variables de la sección 5 y el historial del Anexo B: son las dos partes que se desincronizan primero.*
