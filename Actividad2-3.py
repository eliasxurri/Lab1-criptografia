from scapy.all import rdpcap, ICMP
from termcolor import colored
import re
import sys

def descifrar_cesar(texto, corrimiento):
    resultado = ""
    
    for char in texto:
        if char.isupper():
            resultado += chr((ord(char) - corrimiento - 65) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) - corrimiento - 97) % 26 + 97)
        else:
            resultado += char
    
    return resultado

def es_texto_probable(texto):
    # Simple heurística: verificar si la cadena contiene palabras comunes
    palabras_comunes = ["el", "la", "de", "que", "en", "los", "se", "con", "criptografia", "seguridad", "redes"]
    palabras = texto.lower().split()
    
    contador_palabras_comunes = sum([1 for palabra in palabras if palabra in palabras_comunes])
    
    return contador_palabras_comunes > 1  # Si contiene más de 1 palabra común, es probable

def filtrar_mensaje(mensaje):
    # Filtrar solo letras y espacios
    return re.sub(r'[^a-zA-Z ]', '', mensaje)

def obtener_mensaje_cifrado(texto_cifrado):
    for corrimiento in range(26):
        mensaje_descifrado = descifrar_cesar(texto_cifrado, corrimiento)
        
        if es_texto_probable(mensaje_descifrado):
            print(f"{corrimiento:<2} {colored(mensaje_descifrado, 'green')}")
        else:
            print(f"{corrimiento:<2} {mensaje_descifrado}")

def extraer_datos_icmp(pcap_file):
    paquetes = rdpcap(pcap_file)
    mensaje_cifrado = ""
    
    for paquete in paquetes:
        if ICMP in paquete and paquete[ICMP].type == 8:  # ICMP echo request
            # Extraer los datos del campo ICMP
            mensaje_cifrado += str(bytes(paquete[ICMP].payload).decode(errors="ignore"))
    
    return filtrar_mensaje(mensaje_cifrado)

def main(pcap_file):
    mensaje_cifrado = extraer_datos_icmp(pcap_file)
    print(f"Mensaje cifrado extraído (después de filtrar): {mensaje_cifrado}")
    obtener_mensaje_cifrado(mensaje_cifrado)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 script.py archivo.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    main(pcap_file)
