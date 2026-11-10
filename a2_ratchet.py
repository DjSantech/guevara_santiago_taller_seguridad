"""
A2. Double Ratchet reducido (versión simplificada del algoritmo de Signal).

Todo pasa en un solo proceso y en memoria: no hay red ni servidor. Dos objetos
Ratchet (Alicia y Bob) se pasan mensajes como diccionarios de Python.

Las dos "ruedas" (ratchets):
    1. Rueda simétrica (la misma idea de A1): cada mensaje usa una clave nueva
       sacada de una clave de cadena con HKDF, y la cadena avanza sin vuelta atrás.
    2. Rueda Diffie-Hellman (X25519): cada vez que cambia la dirección de la
       conversación, quien va a escribir genera un PAR DE CLAVES NUEVO. Con eso se
       calcula un secreto nuevo que alguien que robó el estado viejo no conoce.

Simplificaciones (ver informe.md):
    - El secreto inicial compartido (raíz) se recibe ya hecho; en Signal sale de X3DH.
    - Los mensajes deben llegar en orden (no se guardan claves de mensajes saltados).
    - No hay cabeceras cifradas ni autenticación de identidades.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_FIJO = b"\x00" * 12  # cada clave de mensaje se usa UNA sola vez, así que el nonce puede ser fijo


# ---------------- Funciones de apoyo (derivación de claves) ----------------

def _hkdf(material, sal, etiqueta, largo):
    """Aplica HKDF-SHA256 y devuelve 'largo' bytes."""
    return HKDF(algorithm=hashes.SHA256(), length=largo, salt=sal, info=etiqueta).derive(material)


def kdf_raiz(raiz, secreto_dh):
    """Rueda DH: mezcla la clave raíz con el nuevo secreto Diffie-Hellman.

    Devuelve (raiz_nueva, cadena_nueva). Sin conocer secreto_dh no se pueden calcular.
    """
    salida = _hkdf(secreto_dh, raiz, b"A2-raiz", 64)
    return salida[:32], salida[32:]


def kdf_cadena(cadena):
    """Rueda simétrica: de una clave de cadena saca (cadena_siguiente, clave_mensaje)."""
    salida = _hkdf(cadena, None, b"A2-cadena", 64)
    return salida[:32], salida[32:]


def bytes_publica(clave_publica):
    """Pasa una clave pública X25519 a 32 bytes, para ponerla en la cabecera."""
    return clave_publica.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---------------- La clase pedida en el taller ----------------

class Ratchet:
    """Estado de UN participante de la conversación.

    Atributos (el "estado" que un atacante podría robar):
        raiz              clave raíz compartida, cambia en cada cambio de dirección
        mi_privada        mi clave privada X25519 actual
        su_publica        última clave pública X25519 que recibí del otro
        cadena_envio      clave de cadena para mis mensajes (None = toca cambiar de dirección)
        cadena_recepcion  clave de cadena para los mensajes que recibo
        n_envio           número del próximo mensaje que envío en la cadena actual
        n_recepcion       número del próximo mensaje que espero recibir
        publicas_viejas   claves públicas del otro que ya se usaron (para rechazar repeticiones)
    """

    def __init__(self, nombre, raiz, mi_privada=None, su_publica=None):
        """Crea el participante.

        nombre: solo para mostrar.
        raiz: secreto inicial compartido de 32 bytes (simula el resultado de X3DH).
        mi_privada: clave privada inicial (la usa quien RECIBE primero, Bob).
        su_publica: clave pública del otro (la usa quien ENVÍA primero, Alicia).
        """
        self.nombre = nombre
        self.raiz = raiz
        self.mi_privada = mi_privada or X25519PrivateKey.generate()
        self.su_publica = su_publica
        self.cadena_envio = None
        self.cadena_recepcion = None
        self.n_envio = 0
        self.n_recepcion = 0
        self.publicas_viejas = set()

    def mi_publica(self):
        """Devuelve mi clave pública actual en bytes."""
        return bytes_publica(self.mi_privada.public_key())

    def cambiar_direccion(self):
        """Rueda DH del lado que va a ENVIAR.

        Etapas:
            1. Genera un par de claves X25519 NUEVO (la privada vieja se descarta).
            2. Calcula el secreto DH entre mi privada nueva y la pública del otro.
            3. Mezcla ese secreto con la raíz -> raíz nueva + cadena de envío nueva.
            4. Reinicia el contador de mensajes enviados.
        """
        self.mi_privada = X25519PrivateKey.generate()
        secreto = self.mi_privada.exchange(self.su_publica)
        self.raiz, self.cadena_envio = kdf_raiz(self.raiz, secreto)
        self.n_envio = 0

    def enviar(self, texto):
        """Cifra un mensaje y devuelve el diccionario que "viaja" al otro.

        Etapas:
            1. Si no tengo cadena de envío (acabo de recibir), hago cambiar_direccion().
            2. Saco la clave del mensaje de la cadena y avanzo la cadena.
            3. Armo la cabecera: mi clave pública actual + número del mensaje.
            4. Cifro con AES-GCM; la cabecera va como dato asociado (si la cambian, se detecta).
            5. La clave del mensaje se borra (del).
        """
        if self.cadena_envio is None:
            self.cambiar_direccion()
        self.cadena_envio, clave = kdf_cadena(self.cadena_envio)
        cabecera = {"publica": self.mi_publica(), "n": self.n_envio}
        self.n_envio += 1
        cifrado = AESGCM(clave).encrypt(NONCE_FIJO, texto.encode("utf-8"), self._datos_asociados(cabecera))
        del clave  # la clave del mensaje no se guarda
        return {"cabecera": cabecera, "cifrado": cifrado}

    def recibir(self, mensaje):
        """Descifra un mensaje del otro. Si algo está mal lanza ValueError (mensaje rechazado).

        Etapas:
            1. Si la clave pública de la cabecera es NUEVA, el otro cambió de dirección:
               calculo el mismo secreto DH que él y obtengo la cadena de recepción nueva.
            2. Si el número de mensaje ya pasó (o la clave es vieja) -> es una REPETICIÓN.
            3. Saco la clave del mensaje de la cadena de recepción y descifro.
            4. Solo si el descifrado sale bien guardo el estado nuevo
               (así un mensaje alterado no daña el estado).
        """
        cabecera = mensaje["cabecera"]
        publica, n = cabecera["publica"], cabecera["n"]

        if publica in self.publicas_viejas:
            raise ValueError("rechazado: mensaje de una cadena vieja (repetición)")

        # Se trabaja con copias locales; el estado solo se actualiza al final.
        raiz, cadena, esperado = self.raiz, self.cadena_recepcion, self.n_recepcion
        cambio = self.su_publica is None or publica != bytes_publica(self.su_publica)
        if cambio:
            secreto = self.mi_privada.exchange(X25519PublicKey.from_public_bytes(publica))
            raiz, cadena = kdf_raiz(raiz, secreto)
            esperado = 0

        if n < esperado:
            raise ValueError("rechazado: el mensaje ya fue recibido (repetición)")
        if n > esperado:
            raise ValueError("rechazado: mensaje fuera de orden (no soportado en la versión reducida)")

        cadena, clave = kdf_cadena(cadena)
        try:
            texto = AESGCM(clave).decrypt(NONCE_FIJO, mensaje["cifrado"], self._datos_asociados(cabecera))
        except InvalidTag:
            raise ValueError("rechazado: el mensaje fue alterado o la clave no corresponde")
        finally:
            del clave  # la clave del mensaje se borra en cualquier caso

        # Descifrado correcto: ahora sí se guarda el estado nuevo.
        if cambio:
            if self.su_publica is not None:
                self.publicas_viejas.add(bytes_publica(self.su_publica))
            self.su_publica = X25519PublicKey.from_public_bytes(publica)
            self.raiz = raiz
            self.cadena_envio = None  # mi próximo envío hará cambiar_direccion()
        self.cadena_recepcion = cadena
        self.n_recepcion = esperado + 1
        return texto.decode("utf-8")

    @staticmethod
    def _datos_asociados(cabecera):
        """Convierte la cabecera en bytes para autenticarla junto con el cifrado."""
        return cabecera["publica"] + cabecera["n"].to_bytes(4, "big")


def crear_pareja():
    """Prepara a Alicia y Bob con un secreto inicial compartido (simulado).

    En Signal este paso lo hace X3DH; aquí se simula con 32 bytes aleatorios
    y la clave pública inicial de Bob, que Alicia ya conoce.
    """
    raiz = os.urandom(32)
    privada_bob = X25519PrivateKey.generate()
    bob = Ratchet("Bob", raiz, mi_privada=privada_bob)
    alicia = Ratchet("Alicia", raiz, su_publica=privada_bob.public_key())
    return alicia, bob


if __name__ == "__main__":
    # Demostración rápida: 3 mensajes de Alicia, cambio de dirección, 3 de Bob.
    alicia, bob = crear_pareja()
    for i in range(1, 4):
        m = alicia.enviar(f"Hola Bob, mensaje {i}")
        print(f"Alicia -> Bob  | clave pública {m['cabecera']['publica'].hex()[:12]}... | {bob.recibir(m)}")
    for i in range(4, 7):
        m = bob.enviar(f"Hola Alicia, mensaje {i}")
        print(f"Bob -> Alicia  | clave pública {m['cabecera']['publica'].hex()[:12]}... | {alicia.recibir(m)}")
