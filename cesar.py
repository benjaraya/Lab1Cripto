import sys

def encrypt_text(plaintext, n):
    ans = ""
    # iterate over the given text
    for ch in plaintext:
        # check if space is there then simply add space
        if ch == " ":
            ans += " "
        # check if a character is uppercase then encrypt it accordingly 
        elif ch.isupper():
            ans += chr((ord(ch) + n - 65) % 26 + 65)
        # check if a character is lowercase then encrypt it accordingly
        else:
            ans += chr((ord(ch) + n - 97) % 26 + 97)
    
    return ans

if __name__ == "__main__":
    # Verificar que se proporcionen argumentos suficientes
    if len(sys.argv) != 3:
        print()
        sys.exit(1)
    
    # Obtener el texto y el valor de desplazamiento de los argumentos de la línea de comandos
    plaintext = sys.argv[1].strip('"')
    n = int(sys.argv[2])
    
    # Imprimir texto cifrado
    print( encrypt_text(plaintext, n))
