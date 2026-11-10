"""
Pruebas de A1 (cadena de claves simétrica).
Cada función se llama igual que la fila de resultados.csv: A1-01 -> test_A1_01.
"""

import os

from cryptography.exceptions import InvalidTag

from a1_cadena import CadenaDeClaves, cifrar, derivar_clave, descifrar
from registro import registrar


def test_A1_01():
    """Determinismo: misma cadena + mismo índice = misma clave."""
    cadena = os.urandom(32)
    iguales = derivar_clave(cadena, 5) == derivar_clave(cadena, 5)
    obtenido = "misma clave" if iguales else "claves diferentes"
    assert obtenido == registrar("A1-01", obtenido, "HKDF es determinista")


def test_A1_02():
    """Unicidad: 10 mensajes seguidos dan 10 claves diferentes."""
    cadena = CadenaDeClaves(os.urandom(32))
    claves = [cadena.siguiente_clave() for _ in range(10)]
    obtenido = f"{len(set(claves))} claves distintas"   # set() elimina repetidas
    assert obtenido == registrar("A1-02", obtenido, "el índice y la cadena cambian en cada mensaje")


def test_A1_03():
    """Cifrado: emisor y receptor con la misma clave inicial; 10 mensajes ida y vuelta."""
    secreto = os.urandom(32)
    emisor, receptor = CadenaDeClaves(secreto), CadenaDeClaves(secreto)
    correctos = 0
    for i in range(10):
        texto = f"mensaje de prueba {i}"
        clave_e = emisor.siguiente_clave()
        datos = cifrar(clave_e, texto)
        del clave_e                       # el emisor borra la clave al usarla
        clave_r = receptor.siguiente_clave()
        if descifrar(clave_r, datos) == texto:
            correctos += 1
        del clave_r                       # el receptor también la borra
    obtenido = f"{correctos}/10 correctos"
    assert obtenido == registrar("A1-03", obtenido, "AES-GCM con una clave distinta por mensaje")


def test_A1_04():
    """Borrado: tras usar la clave 0 y borrarla, quien robe el estado actual no la recupera.

    El atacante se queda con la cadena actual y prueba todas las claves que puede
    derivar con ella (índices 0..99). Ninguna descifra el mensaje 0.
    """
    cadena = CadenaDeClaves(os.urandom(32))
    clave = cadena.siguiente_clave()
    mensaje_0 = cifrar(clave, "secreto del mensaje 0")
    del clave                                     # clave usada y borrada

    cadena_robada = cadena.cadena                 # el atacante roba el estado de ahora
    recuperada = False
    for indice in range(100):
        try:
            descifrar(derivar_clave(cadena_robada, indice), mensaje_0)
            recuperada = True
        except InvalidTag:
            pass
    obtenido = "recuperable" if recuperada else "no recuperable"
    assert obtenido == registrar("A1-04", obtenido,
                                 "HKDF es de un solo sentido: la cadena nueva no lleva a la vieja")
