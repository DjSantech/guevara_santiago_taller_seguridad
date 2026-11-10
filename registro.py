"""
Registro de resultados de las pruebas.

Cada prueba llama a registrar(id_prueba, obtenido). Al terminar pytest,
conftest.py llama a guardar_archivos(), que escribe:
    - log_pruebas.json  (lista de objetos: prueba, esperado, obtenido, estado)
    - resultados.csv    (la plantilla del taller con obtenido, estado y comentario llenos)
"""

import csv
import json
import os

CARPETA = os.path.dirname(os.path.abspath(__file__))

ENCABEZADO = ["id_prueba", "algoritmo", "propiedad", "descripcion",
              "esperado", "obtenido", "estado", "comentario"]

# Las 9 filas de la plantilla del taller (sin cambiar el texto).
PLANTILLA = [
    ["A1-01", "A1", "determinismo", "Misma cadena e índice producen la misma clave", "misma clave"],
    ["A1-02", "A1", "unicidad", "10 claves de mensaje distintas", "10 claves distintas"],
    ["A1-03", "A1", "cifrado", "Cifrar y descifrar 10 mensajes", "10/10 correctos"],
    ["A1-04", "A1", "borrado", "Clave usada y luego borrada no se recupera", "no recuperable"],
    ["A2-01", "A2", "descifrado", "Descifrar los 6 mensajes", "6/6 correctos"],
    ["A2-02", "A2", "integridad", "Un byte alterado del ciphertext", "rechazado"],
    ["A2-03", "A2", "repetición", "Mensaje reenviado", "rechazado"],
    ["A2-04", "A2", "forward secrecy", "Estado robado tras mensaje 3 no descifra mensaje 1", "no descifrable"],
    ["A2-05", "A2", "post-compromise", "Estado robado antes del cambio de dirección no descifra tras él",
     "no descifrable"],
]

ESPERADOS = {fila[0]: fila[4] for fila in PLANTILLA}

resultados = {}  # id_prueba -> {"obtenido": ..., "comentario": ...}


def registrar(id_prueba, obtenido, comentario=""):
    """Guarda lo que obtuvo la prueba y devuelve el valor esperado (para el assert)."""
    resultados[id_prueba] = {"obtenido": obtenido, "comentario": comentario}
    return ESPERADOS[id_prueba]


def estado(id_prueba):
    """OK si lo obtenido es igual a lo esperado; FALLA en cualquier otro caso."""
    r = resultados.get(id_prueba)
    return "OK" if r and r["obtenido"] == ESPERADOS[id_prueba] else "FALLA"


def guardar_archivos():
    """Escribe log_pruebas.json y resultados.csv en la carpeta del proyecto (UTF-8)."""
    log = []
    with open(os.path.join(CARPETA, "resultados.csv"), "w", encoding="utf-8", newline="") as f:
        escritor = csv.writer(f)
        escritor.writerow(ENCABEZADO)
        for id_prueba, algoritmo, propiedad, descripcion, esperado in PLANTILLA:
            r = resultados.get(id_prueba, {"obtenido": "no ejecutada",
                                           "comentario": "la prueba no llegó a registrar resultado"})
            est = estado(id_prueba)
            escritor.writerow([id_prueba, algoritmo, propiedad, descripcion,
                               esperado, r["obtenido"], est, r["comentario"]])
            log.append({"prueba": id_prueba, "esperado": esperado,
                        "obtenido": r["obtenido"], "estado": est})
    with open(os.path.join(CARPETA, "log_pruebas.json"), "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
