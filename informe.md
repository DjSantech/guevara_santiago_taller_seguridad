# Informe: seguridad en mensajería (E2EE y forward secrecy)

Santiago Guevara. Sistemas Distribuidos, noviembre de 2026.

## Qué se implementó

Todo se hizo con código propio, en local y con datos inventados (Alicia y Bob). No se tocaron apps reales ni datos personales (Ley 1581). La criptografía viene de la biblioteca estándar `cryptography`; no se implementó ningún algoritmo criptográfico desde cero.

**A1, cadena de claves simétrica (`a1_cadena.py`).**
- `derivar_clave(cadena, indice)`: clave del mensaje con HKDF-SHA256, con el índice dentro de la etiqueta `info`.
- `avanzar_cadena(cadena)`: siguiente clave de cadena (HKDF, de un solo sentido).
- `cifrar(clave, texto)` / `descifrar(clave, datos)`: AES-256-GCM con nonce aleatorio.
- Clase `CadenaDeClaves`: entrega una clave por mensaje, sobrescribe la cadena y las claves usadas se borran con `del`.

**A2, Double Ratchet reducido (`a2_ratchet.py`).**
- Clase `Ratchet` con `enviar`, `recibir` y `cambiar_direccion`.
- `cambiar_direccion()` genera un par **X25519 nuevo**, calcula el secreto DH con la pública del otro y lo mezcla con la raíz (HKDF) → raíz nueva + cadena de envío nueva.
- `enviar()` saca la clave del mensaje de la cadena (HKDF), pone en la cabecera la pública actual y el número `n`, y cifra con AES-GCM usando la cabecera como dato asociado.
- `recibir()` detecta la pública nueva (el otro cambió de dirección), rechaza números ya usados (repetición) y textos alterados (InvalidTag), y **solo actualiza el estado si el descifrado sale bien**.
- Escenario: 6 mensajes en un solo proceso, 3 de Alicia → Bob, cambio de dirección y 3 de Bob → Alicia.

**Pruebas.** `test_a1.py` y `test_a2.py` tienen una función por fila (`test_A1_01` … `test_A2_05`). `registro.py` y `conftest.py` escriben `resultados.csv` y `log_pruebas.json` al terminar `python -m pytest -q`.

**Resultado: 9 de 9 pruebas en OK (100 %).** No hay ninguna FALLA que justificar.

| Prueba | Esperado | Obtenido | Estado |
|---|---|---|---|
| A1-01 | misma clave | misma clave | OK |
| A1-02 | 10 claves distintas | 10 claves distintas | OK |
| A1-03 | 10/10 correctos | 10/10 correctos | OK |
| A1-04 | no recuperable | no recuperable | OK |
| A2-01 | 6/6 correctos | 6/6 correctos | OK |
| A2-02 | rechazado | rechazado | OK |
| A2-03 | rechazado | rechazado | OK |
| A2-04 | no descifrable | no descifrable | OK |
| A2-05 | no descifrable | no descifrable | OK |

Para que el "no descifrable" de A2-04 y A2-05 no fuera casualidad, el atacante de la prueba usa el estado robado de dos formas (pedirle a `recibir` que lo lea, y fuerza bruta de 50 claves de la cadena y de todas las combinaciones DH que puede hacer). También se comprobó aparte que el mismo ataque **sí** lee el mensaje cuando se le da la clave correcta (control positivo).

## Diferencias

Diferencias frente al Double Ratchet real de Signal:

| Signal | Este taller |
|---|---|
| Secreto inicial con X3DH (claves de identidad, prekeys firmadas) | Raíz de 32 bytes aleatorios compartida directamente (`crear_pareja`) |
| KDF de cadena con HMAC-SHA256 (constantes 0x01 y 0x02) | HKDF-SHA256 con etiquetas de texto |
| Guarda claves de mensajes saltados (llegan fuera de orden) | Exige orden; un mensaje adelantado se rechaza |
| Cabeceras con contador de la cadena anterior (`PN`) y opción de cifrarlas | Cabecera con solo la pública y `n`, sin cifrar |
| AEAD con AES-CBC + HMAC y nonce/IV derivados | AES-GCM con nonce fijo (válido porque cada clave se usa una vez) |
| Red, servidor y varios dispositivos | Un solo proceso en memoria |

## Limitaciones

- **Sin autenticación de identidades:** no hay verificación de números de seguridad, así que un atacante activo en medio al inicio no se detectaría.
- **Borrado de memoria:** `del` en Python quita la referencia, pero no garantiza que los bytes se borren físicamente de la RAM (Python no permite borrar memoria de forma segura). La propiedad se demuestra a nivel lógico: el estado robado ya no contiene la clave.
- **Post-compromiso limitado a atacante pasivo:** si el atacante con el estado robado se mete activamente en la conversación antes del cambio de dirección, puede seguir suplantando. Signal tampoco cubre ese caso.
- **Orden estricto:** sin soporte de mensajes perdidos o desordenados.
- **Metadatos:** como en cualquier E2EE, quién habla con quién y cuándo no se protege.
- Prueba de 6 mensajes y un solo cambio de dirección; no se midió rendimiento.
