import struct
import time
from scapy.all import *
import sys

# Variable global para el identificador ICMP
icmp_identifier = 1

def get_timestamp_bytes():
    # Obtener el tiempo actual
    tiempo_actual = int(time.time())  # Obtener el timestamp actual en segundos

    # Convertir el tiempo actual a formato hexadecimal
    timestamp_bytes = struct.pack("<LL", tiempo_actual, 0)
    
    return timestamp_bytes

def hide_data_in_packets(data):
    global icmp_identifier  # Usar la variable global icmp_identifier
    target_ip = "127.0.0.1"  # Dirección IP de destino
    
    for index, char in enumerate(data):
        # Obtener los bytes de timestamp actualizados
        timestamp_bytes = get_timestamp_bytes()

        # Construir el paquete ICMP (echo request) como un ping normal
        ping_data = bytes.fromhex("0800280000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")

        # Modificar el campo "id" del paquete ICMP (2 bytes)
        id_value = icmp_identifier  # Usar el identificador ICMP global
        icmp_packet = ICMP(id=id_value)

        # Modificar el campo "seq" del paquete ICMP (2 bytes)
        seq_value = index + 1  # Ajustar el valor de secuencia
        seq_value *= 256
        icmp_packet.seq = seq_value

        # Convertir el caracter a bytes
        char_byte = bytes([ord(char)])

        # Agregar los bytes dados antes de los datos
        modified_data = timestamp_bytes[:4] + bytes(4) + char_byte + ping_data[0:47]  # Tomamos 48 bytes de datos originales

        # Construir el paquete ICMP con los datos modificados
        packet = IP(dst=target_ip, id=icmp_identifier) / icmp_packet / modified_data

        # Incrementar el identificador ICMP para el próximo paquete
        icmp_identifier += 1

        # Enviar el paquete
        send(packet, verbose=False)
        print(f"Se envió 1 paquete.")
        time.sleep(1)

def main():
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv5.py 'data input'")
        return

    data = sys.argv[1]
    hide_data_in_packets(data)

if __name__ == "__main__":
    main()
