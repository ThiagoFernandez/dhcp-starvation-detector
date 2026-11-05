from argparse import Namespace
from argparse import ArgumentParser
import sys
import time
import logging 
import json
from datetime import datetime, timezone
from scapy.all import Ether, DHCP, sniff, Scapy_Exception

#const
IFACE="virbrrz"  # evito el footgun operativo
FILTRO = "udp and (port 67 or port 68)"
STARVATION_THRESHOLD = 20
STARVATION_WINDOWS = 5
ALERT_COOLDOWN = 5
TRACKER_CAP = 1000 # Límite reubicado para evitar OOM/CPU lock en dict_macs

#ARGS

def create_args()->Namespace:
    p = ArgumentParser(description="STARVATION DETECTOR")
    p.add_argument("-i", "--iface", default=IFACE)
    p.add_argument("-d", "--duration", type=int, default=0, help="segundos; 0=infinito")
    p.add_argument("-s", "--silence", type=int, default=0, help="silencio; 1=si | 0=no")
    return p.parse_args()

# logging

class JSONFormatter(logging.Formatter):
    """
    Formatter para archivo.
    Emite un JSONL (JSON Lines) estructurado por cada evento. Combina el 
    mensaje base con los campos inyectados via `extra={"alert_meta": {...}}`.
    """
    def format(self, record):
        log_obj = {
            # Usamos el timestamp de creación del log directamente en ISO 8601
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage()
        }

        # Si el evento trae metadata estructurada, la fusionamos al nivel raiz del JSON
        if hasattr(record, "alert_meta") and record.alert_meta:
            log_obj.update(record.alert_meta)

        return json.dumps(log_obj, ensure_ascii=False)

def configure_logger(name="dhcp_starvation", silent=False):
    logger = logging.getLogger(name)

    if not logger.hasHandlers():
        # 1. Handler de Consola (Texto plano, sin colores)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

        # 2. Handler de Archivo: Exclusivo para alertas (JSONL)
        file_handler = logging.FileHandler("dhcp_starvation_alerts.jsonl")
        file_handler.setLevel(logging.WARNING)  # Filtro independiente: solo alertas
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

        logger.propagate = False

    if silent:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)

    return logger

# Instanciamos el logger globalmente
logger = None

# estado

def crear_estado(args):
    return {
        #parametros
        "interface": args.iface,
        "duration": args.duration if args.duration > 0 else None,
        "silence":  args.silence
    }

#global
dict_macs: dict = {} #mac->time
ultima_alerta: dict = {}
estado:dict = {}


# detector
def detect(pkt):

    if not DHCP in pkt: # debe contener dhcp
        return

    opciones = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    tipo = opciones.get("message-type")
    if tipo not in (1,3): # debe ser un msj de cliente
        return
    
    now = time.time()
    mac = pkt[Ether].src
    starvation_check(mac, now)

    
def starvation_check(mac, now):
    """Cardinalidad de MACs distintas sobre una ventana deslizante."""
    dict_macs[mac] = now  

    if len(dict_macs) <= STARVATION_THRESHOLD:
        return  # O(1), caso comun

    # Limpieza de la ventana O(n)
    vencidas = [m for m, t in dict_macs.items() if now - t >= STARVATION_WINDOWS]
    for m in vencidas:
        del dict_macs[m]

    if len(dict_macs) > STARVATION_THRESHOLD:
        alert("DHCP STARVATION", None, now)
        
    # Limpieza dura para evitar colapso de CPU/Memoria bajo un flood muy intenso
    # Si ingresan miles de MACs distintas en < 5s, se vacía para resetear la ventana
    if len(dict_macs) > TRACKER_CAP:
        dict_macs.clear()

def alert(tipo, origen, now):
    """
    Imprime y loguea como mucho una alerta cada ALERT_COOLDOWN por (tipo, origen).
    """
    clave = (tipo, origen)
    if now - ultima_alerta.get(clave, 0.0) < ALERT_COOLDOWN:
        return
    
    ultima_alerta[clave] = now
    peak_macs = len(dict_macs)
    
    # Escribimos el log estructurado pasando el contexto completo
    logger.warning(
        f"[{tipo}] {peak_macs} MACs distintas en {STARVATION_WINDOWS}s",
        extra={
            "alert_meta": {
                "event_type": tipo,
                "severity_peak": peak_macs,
                "context": {
                    "threshold": STARVATION_THRESHOLD,
                    "window_sec": STARVATION_WINDOWS
                }
            }
        }
    )


# sniff
def sniff_network():
    try:
        sniff(
            filter=FILTRO,
            prn=detect,
            store=False,
            iface=estado["interface"],
            timeout=estado["duration"],
        )

    except KeyboardInterrupt:
        print("Cerrando programa...")
    except PermissionError:
        print("Error: permisos insuficientes")
    except Scapy_Exception as e:
        print("Error de Scapy:", e)
    except OSError as e:
        print("Error de red:", e)
    except Exception as e:
        print("Error global:", e)


def main():
    global estado, logger
    argumentos = create_args()
    estado = crear_estado(argumentos)
    logger = configure_logger(silent=estado["silence"])
    if not estado["silence"]: # False es 0 y TRue es 1
        print(f"Arrancando en: {estado['interface']}")

    sniff_network()


if __name__ == "__main__":
    main()