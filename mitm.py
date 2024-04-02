import pyshark
import sys

def decode_cesar(encoded_text):
    decoded_lines = []
    for shift in range(26):
        decoded_text = ""
        for char in encoded_text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                decoded_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                decoded_char = char
            decoded_text += decoded_char
        decoded_lines.append(decoded_text)
    return decoded_lines

def read_pcapng(file_path):
    packets = pyshark.FileCapture(file_path)
    decoded_text = ""

    for packet in packets:
        if 'icmp' in packet and packet.icmp.type == '8':  # ICMP tipo 8 es un "Echo Request"
            if hasattr(packet.icmp, 'data'):
                # Obtener los primeros dos caracteres hexadecimales de los datos ICMP
                hex_chars = packet.icmp.data[:2]

                # Decodificar los caracteres hexadecimales a una letra
                decoded_char = chr(int(hex_chars, 16))

                # Agregar la letra decodificada al texto
                decoded_text += decoded_char

    return decoded_text

def main():
    if len(sys.argv) != 2:
        print("Uso: python programa.py archivo.pcapng")
        return

    file_path = sys.argv[1]
    decoded_text = read_pcapng(file_path)
    
    decoded_lines = decode_cesar(decoded_text)
    for i, line in enumerate(decoded_lines[1:], start=2):  # Comenzar desde la segunda línea
        print(f"{i-1}: {line}")

if __name__ == "__main__":
    main()
