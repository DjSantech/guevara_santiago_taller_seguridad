"""
Pruebas de A2 (Double Ratchet reducido, 6 mensajes, un cambio de dirección).
Cada función se llama igual que la fila de resultados.csv: A2-01 -> test_A2_01.

Conversación usada en todas las pruebas:
    mensajes 1, 2, 3: Alicia -> Bob
    (cambio de dirección: Bob genera un par X25519 nuevo)
    mensajes 4, 5, 6: Bob -> Alicia
"""

import copy

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from a2_ratchet import NONCE_FIJO, Ratchet, crear_pareja, kdf_cadena, kdf_raiz
from registro import registrar


def intentar_recibir(receptor, mensaje):
    """Devuelve el texto si el receptor lo acepta, o None si lo rechaza."""
    try:
        return receptor.recibir(mensaje)
    except ValueError:
        return None


def probar_cadena(cadena, mensaje, intentos=50):
    """Ataque de fuerza bruta: deriva las próximas 'intentos' claves de una cadena
    y prueba cada una sobre el mensaje. Devuelve el texto si alguna sirve, o None."""
    for _ in range(intentos):
        cadena, clave = kdf_cadena(cadena)
        try:
            return AESGCM(clave).decrypt(NONCE_FIJO, mensaje["cifrado"],
                                         Ratchet._datos_asociados(mensaje["cabecera"]))
        except InvalidTag:
            pass
    return None


def test_A2_01():
    """Descifrado: los 6 mensajes llegan bien en las dos direcciones."""
    alicia, bob = crear_pareja()
    correctos = 0
    for i in range(1, 4):
        if bob.recibir(alicia.enviar(f"mensaje {i}")) == f"mensaje {i}":
            correctos += 1
    for i in range(4, 7):
        if alicia.recibir(bob.enviar(f"mensaje {i}")) == f"mensaje {i}":
            correctos += 1
    obtenido = f"{correctos}/6 correctos"
    assert obtenido == registrar("A2-01", obtenido, "3 mensajes por dirección con un cambio de par X25519")


def test_A2_02():
    """Integridad: se cambia un byte del ciphertext y Bob debe rechazarlo."""
    alicia, bob = crear_pareja()
    mensaje = alicia.enviar("transferir 100")
    alterado = bytearray(mensaje["cifrado"])
    alterado[0] ^= 0x01                                # se voltea un bit del primer byte
    falso = {"cabecera": mensaje["cabecera"], "cifrado": bytes(alterado)}
    obtenido = "aceptado" if intentar_recibir(bob, falso) is not None else "rechazado"
    # Extra: el original sigue funcionando (el mensaje alterado no dañó el estado).
    assert bob.recibir(mensaje) == "transferir 100"
    assert obtenido == registrar("A2-02", obtenido, "AES-GCM detecta el cambio (InvalidTag)")


def test_A2_03():
    """Repetición: un mensaje ya recibido se reenvía y debe rechazarse."""
    alicia, bob = crear_pareja()
    mensaje = alicia.enviar("hola")
    bob.recibir(mensaje)                                # primera vez: se acepta
    obtenido = "aceptado" if intentar_recibir(bob, mensaje) is not None else "rechazado"
    assert obtenido == registrar("A2-03", obtenido,
                                 "el número n ya pasó y su clave fue borrada")


def test_A2_04():
    """Forward secrecy: el atacante roba el estado de Bob tras el mensaje 3
    y trata de leer el mensaje 1 (que grabó de la red)."""
    alicia, bob = crear_pareja()
    m1 = alicia.enviar("mensaje 1")
    bob.recibir(m1)
    bob.recibir(alicia.enviar("mensaje 2"))
    bob.recibir(alicia.enviar("mensaje 3"))

    robado = copy.copy(bob)                             # el atacante copia TODO el estado
    leido = intentar_recibir(robado, m1)                # a) pedirle al estado robado que lo lea
    if leido is None:                                   # b) fuerza bruta con la cadena robada
        leido = probar_cadena(robado.cadena_recepcion, m1)
    obtenido = "descifrable" if leido is not None else "no descifrable"
    assert obtenido == registrar("A2-04", obtenido,
                                 "la clave del mensaje 1 se borró y la cadena solo avanza hacia adelante")


def test_A2_05():
    """Post-compromise: el atacante roba el estado de Bob ANTES del cambio de dirección.
    Bob genera un par X25519 nuevo y envía el mensaje 4. El atacante no lo descifra."""
    alicia, bob = crear_pareja()
    for i in range(1, 4):
        bob.recibir(alicia.enviar(f"mensaje {i}"))

    robado = copy.copy(bob)                             # estado robado antes del cambio
    m4 = bob.enviar("mensaje 4")                        # aquí Bob hace cambiar_direccion()
    assert alicia.recibir(m4) == "mensaje 4"            # el destinatario real sí lo lee

    # El atacante tiene: raíz vieja, privada vieja de Bob, pública de Alicia,
    # y ve en la cabecera la pública NUEVA de Bob. Prueba todas las combinaciones DH que puede hacer.
    leido = intentar_recibir(robado, m4)
    publica_nueva_bob = X25519PublicKey.from_public_bytes(m4["cabecera"]["publica"])
    for publica in (robado.su_publica, publica_nueva_bob):
        if leido is None:
            secreto = robado.mi_privada.exchange(publica)
            _, cadena = kdf_raiz(robado.raiz, secreto)
            leido = probar_cadena(cadena, m4)
    obtenido = "descifrable" if leido is not None else "no descifrable"
    assert obtenido == registrar("A2-05", obtenido,
                                 "la nueva privada X25519 de Bob no estaba en el estado robado")
