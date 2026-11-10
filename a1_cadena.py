"""
A1. Cadena de claves simétrica (versión simplificada de la "cadena" de Signal).

Idea en una frase:
    De una clave de cadena se saca una clave distinta para CADA mensaje (con HKDF),
    la clave se usa una sola vez y después se borra.

Bibliotecas usadas (estándar, no se implementa criptografía desde cero):
    - HKDF con SHA-256 (RFC 5869)   -> para derivar claves.
    - AES-GCM de 256 bits           -> para cifrar y detectar alteraciones.
    Ambas vienen del paquete "cryptography".
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TAMANO_CLAVE = 32   # 32 bytes = 256 bits
TAMANO_NONCE = 12   # AES-GCM usa un número único (nonce) de 12 bytes por cifrado


def _hkdf(material, etiqueta):
    """Función auxiliar: aplica HKDF-SHA256 a 'material' y devuelve 32 bytes.

    'etiqueta' (el parámetro info de HKDF) sirve para que, a partir del mismo
    material, salgan claves diferentes según para qué se usen.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=TAMANO_CLAVE, salt=None, info=etiqueta)
    return hkdf.derive(material)


def derivar_clave(cadena, indice):
    """Deriva la clave del mensaje número 'indice' a partir de la clave de cadena.

    Parámetros:
        cadena (bytes): clave de cadena actual (32 bytes).
        indice (int): número del mensaje (0, 1, 2, ...).

    Devuelve:
        bytes: clave de mensaje de 32 bytes.

    Es determinista: la misma cadena y el mismo índice siempre dan la misma clave
    (así el emisor y el receptor llegan a la misma clave sin enviarla por la red).
    Como el índice va dentro de la etiqueta de HKDF, cada índice da una clave distinta.
    """
    return _hkdf(cadena, b"A1-mensaje-" + str(indice).encode())


def avanzar_cadena(cadena):
    """Calcula la SIGUIENTE clave de cadena a partir de la actual.

    HKDF es de un solo sentido: con la cadena nueva no se puede volver a la vieja.
    Eso es lo que da el secreto hacia adelante (forward secrecy).
    """
    return _hkdf(cadena, b"A1-cadena")


def cifrar(clave, texto):
    """Cifra un texto con AES-GCM usando la clave del mensaje.

    Parámetros:
        clave (bytes): clave de mensaje de 32 bytes (sale de derivar_clave).
        texto (str): mensaje en claro.

    Devuelve:
        bytes: nonce (12 bytes) + texto cifrado + etiqueta de autenticación.
    """
    nonce = os.urandom(TAMANO_NONCE)  # número aleatorio que no se repite
    return nonce + AESGCM(clave).encrypt(nonce, texto.encode("utf-8"), None)


def descifrar(clave, datos):
    """Hace lo contrario de cifrar(): separa el nonce y descifra.

    Si los datos fueron alterados o la clave no es la correcta, AES-GCM lanza
    cryptography.exceptions.InvalidTag (el mensaje se rechaza).
    """
    nonce, cifrado = datos[:TAMANO_NONCE], datos[TAMANO_NONCE:]
    return AESGCM(clave).decrypt(nonce, cifrado, None).decode("utf-8")


class CadenaDeClaves:
    """Lleva la cadena de un lado de la conversación y borra lo que ya se usó.

    Funcionamiento por etapas, para cada mensaje:
        1. clave = derivar_clave(cadena, indice)   -> clave solo para este mensaje
        2. cadena = avanzar_cadena(cadena)         -> la cadena vieja se reemplaza (se pierde)
        3. indice = indice + 1
        4. Quien use la clave la borra después de cifrar/descifrar.
    """

    def __init__(self, clave_inicial):
        self.cadena = clave_inicial  # secreto compartido inicial (simulado)
        self.indice = 0

    def siguiente_clave(self):
        """Entrega la clave del próximo mensaje y avanza la cadena (sin vuelta atrás)."""
        clave = derivar_clave(self.cadena, self.indice)
        self.cadena = avanzar_cadena(self.cadena)  # se sobrescribe: la cadena vieja desaparece
        self.indice += 1
        return clave
