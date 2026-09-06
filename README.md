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
