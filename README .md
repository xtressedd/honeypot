# Proyecto Honeypot con Suricata

Este proyecto implementa un honeypot pasivo en un entorno Docker, utilizando Suricata como motor de detección de intrusiones (IDS). Su principal objetivo es identificar patrones de comportamiento malicioso mediante reglas personalizadas, registrar eventos y establecer una base para ejecutar medidas reactivas como el bloqueo de IPs o la generación de alertas automatizadas.

## Tecnologías utilizadas

- **Suricata 7.0.9**: Motor IDS/IPS/NSM para análisis de tráfico en tiempo real.
- **Docker & Docker Compose**: Contenerización de Suricata y scripts de gestión.
- **iptables** (en contenedor "blocker"): Herramienta de bloqueo de IPs.
- **Bash/JQ**: Automatización y tratamiento de logs.

## Estructura del proyecto

```
honeypot-project/
├── docker-compose.yml
├── logs/                       # Directorio de salida de logs de Suricata
├── rules/
│   └── custom.rules            # Reglas personalizadas para detectar ataques
├── scripts/
│   ├── block_and_alert.sh     # Script (placeholder) para bloquear IPs
│   └── Dockerfile.blocker     # Dockerfile para el contenedor de acciones
└── suricata/
    ├── Dockerfile             # Dockerfile para el contenedor de Suricata
    ├── suricata.yaml          # Configuración principal de Suricata
    ├── classification.config  # Configuraciones auxiliares requeridas por Suricata
    ├── reference.config
    └── threshold.config
```

## Reglas de ejemplo (`custom.rules`)

```text
alert icmp any any -> any any (msg:"ICMP Echo Request detected"; itype:8; sid:1000001; rev:1;)
alert tcp any any -> any 22 (msg:"SSH connection attempt detected"; flags:S; sid:1000002; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP request detected"; sid:1000003; rev:1;)
alert udp any any -> any 53 (msg:"DNS request detected"; sid:1000004; rev:1;)
```

Estas reglas permiten detectar escaneos de red, intentos de conexión SSH, actividad HTTP no esperada y consultas DNS desde nodos no autorizados.

## Ejecución del sistema

1. Clona el repositorio:

```bash
git clone https://github.com/tu_usuario/tu_repo.git
cd honeypot-project
```

2. Construye y ejecuta los contenedores:

```bash
sudo docker compose up --build
```

3. Verifica que Suricata haya cargado las reglas:

```bash
sudo docker compose exec suricata bash
suricata -T -c /etc/suricata/suricata.yaml -v
```

Debe mostrar:

```
1 rule files processed. 4 rules successfully loaded
```

4. Los logs se generan en `logs/eve.json` y `logs/fast.log`.

## Consideraciones técnicas

- Se ha utilizado `network_mode: host` para que el contenedor de Suricata pueda inspeccionar interfaces de red reales (como `wlo1`).
- El volumen `./rules:/etc/suricata/rules` permite que las reglas sean editables desde el host y cargadas directamente por el contenedor.
- El contenedor de "blocker" está preparado para ejecutar scripts reactivos en base a eventos generados por Suricata, aunque actualmente sólo actúa como placeholder.

## Posibles extensiones

- Integración con ELK Stack para visualización y análisis avanzado.
- Automatización de bloqueos con `fail2ban` o scripts personalizados.
- Notificación por correo de alertas críticas.
- Reglas IoC actualizadas con feeds de amenazas conocidos.

## Autor

Domingo, estudiante de ciberseguridad y administrador de sistemas.

---

> Este proyecto ha sido desarrollado como parte de un entorno de pruebas y formación en detección de intrusiones. Se recomienda su uso en entornos controlados y de laboratorio.
