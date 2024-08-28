from scapy.all import *
import time

def cifrar_cesar(texto, corrimiento):
    cifrado = []
    for char in texto:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            desplazado = (ord(char) - base + corrimiento) % 26 + base
            cifrado.append(chr(desplazado))
        else:
            cifrado.append(char)
    return ''.join(cifrado)

def enviar_icmp_paquete(texto_cifrado):
    for char in texto_cifrado:
        # Crear el paquete ICMP
        paquete = IP(dst="8.8.8.8") / ICMP() / Raw(load=char)
        print(f"Enviando paquete ICMP con dato: {char}")
        send(paquete)
        time.sleep(1)  # Espera para no sobrecargar la red

def mostrar_pings():
    print("Paquetes ICMP reales antes y después:")
    # Enviar un ping real a modo de comparación
    os.system("ping -n 4 8.8.8.8")

def main():
    texto = input("Introduce el texto a cifrar: ")
    corrimiento = int(input("Introduce el corrimiento (número entero): "))
    
    texto_cifrado = cifrar_cesar(texto, corrimiento)
    print("Texto cifrado:", texto_cifrado)
    
    print("\nEnviando paquetes ICMP...")
    enviar_icmp_paquete(texto_cifrado)
    
    print("\nMostrando pings reales antes y después...")
    mostrar_pings()

if __name__ == "__main__":
    main()
