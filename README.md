# DHCP Starvation Detector

Detector host-side de **DHCP starvation** por **cardinalidad de MACs**: escucha el
tráfico DHCP de una interfaz y alerta cuando aparecen demasiadas MAC de origen
distintas pidiendo dirección dentro de una ventana corta de tiempo. Es la versión
en software de la lógica de **Port Security** (máximo N MAC por puerto): no mira
*quién* es cada cliente (identidad falsificable), mira *cuántos distintos* aparecen
por unidad de tiempo — la señal que un ataque de starvation no puede bajar sin dejar
de agotar el pool.

> ⚠️ Herramienta de laboratorio. Pensado para la red aislada `redzone` (10.10.10.0/24).

## Por qué cardinalidad y no identidad

Un detector por identidad (whitelist de IP/MAC, o chequear `chaddr != Ether.src`) lo
evade un atacante prolijo que mantiene las MAC coherentes. La cardinalidad es robusta
porque el **objetivo** del ataque lo obliga: para secar un pool de ~100 IPs hay que
presentar ~100 identidades distintas. No se puede agotar el pool con pocas MAC → el
volumen de MAC distintas es la huella que el ataque no puede esconder.

## Cómo funciona

1. `sniff` con filtro BPF `udp and (port 67 or port 68)`.
2. Por cada paquete: ignora lo que no sea DHCP y lo que no sea `message-type`
   **1 (Discover)** o **3 (Request)** — los mensajes de cliente.
3. Guarda la MAC de origen L2 (`pkt[Ether].src`) en un dict `MAC -> timestamp`.
4. **Ventana deslizante:** cuando el dict supera el umbral, limpia las MAC vencidas
   (vistas hace más de `STARVATION_WINDOWS` segundos). El caso común (por debajo del
   umbral) retorna en O(1); la limpieza O(n) solo corre cuando hace falta.
5. Si tras limpiar siguen superando el umbral → **alerta**.
6. **Cooldown:** como mucho una alerta cada `ALERT_COOLDOWN` segundos (evita cientos
   de alertas por segundo durante el flood).
7. **Guard de memoria:** si entran más de `TRACKER_CAP` MAC distintas (flood extremo),
   se vacía el tracker *después* de alertar, para no consumir RAM sin techo.

Las alertas se escriben en consola (texto plano) y en `dhcp_starvation_alerts.jsonl`
(una línea JSON por alerta, con timestamp ISO-8601, pico de MAC y contexto).

## Requisitos

- Python 3 + scapy (`pip install scapy`)
- Privilegios root (sockets crudos)

## Uso

```bash
sudo python3 main.py [-i IFACE] [-d DURACION] [-s SILENCE]
```

| Flag | Default | Qué hace |
|---|---|---|
| `-i`, `--iface` | `virbrrz` | Interfaz donde escuchar. En el host del lab es el bridge `virbrrz`. |
| `-d`, `--duration` | `0` | Segundos a correr. `0` = infinito (hasta Ctrl+C). |
| `-s`, `--silence` | `0` | `1` = modo silencio (solo alertas, sin el log INFO de arranque). |

## Parámetros de detección (constantes, arriba del script)

| Constante | Valor | Significado |
|---|---|---|
| `STARVATION_THRESHOLD` | 20 | MAC distintas en la ventana que disparan la alerta. |
| `STARVATION_WINDOWS` | 5 | Tamaño de la ventana deslizante, en segundos. |
| `ALERT_COOLDOWN` | 5 | Segundos mínimos entre dos alertas. |
| `TRACKER_CAP` | 1000 | Tope de MAC en memoria; al superarlo se vacía el tracker. |

> Ajuste: 20 MAC distintas en 5 s es claramente anómalo en una LAN doméstica. Subí el
> umbral si tu red tiene muchos clientes legítimos rotando rápido.

## Ejemplo

Con un ataque de starvation corriendo contra el servidor DHCP del segmento:

```
$ sudo python3 main.py
Arrancando en: virbrrz
[DHCP STARVATION] 21 MACs distintas en 5s
```

Línea en `dhcp_starvation_alerts.jsonl`:

```json
{"timestamp": "2026-11-05T19:24:36.767793+00:00", "level": "WARNING", "msg": "[DHCP STARVATION] 21 MACs distintas en 5s", "event_type": "DHCP STARVATION", "severity_peak": 21, "context": {"threshold": 20, "window_sec": 5}}
```

## Limitaciones

- **Host-side:** en una red conmutada el switch entrega el tráfico unicast solo al
  puerto destino, así que un detector en un host puede no ver todo el DHCP del
  segmento. La mitigación real de catálogo es **DHCP Snooping + Port Security en el
  switch** (Cisco), que confía por puerto físico — no falsificable desde software.
  Este detector es la versión host del mismo concepto, útil para aprender la señal.
- Detecta el **volumen** del ataque; no identifica al atacante individual (justamente
  porque su fuerza es no depender de la identidad).
