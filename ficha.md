# Ficha: cifrado extremo a extremo y forward secrecy

Santiago Guevara. Sistemas Distribuidos, noviembre de 2026.

## Definición

**¿Qué protege el cifrado extremo a extremo (E2EE) y qué no protege?**
En E2EE el mensaje se cifra en el dispositivo del emisor y solo el dispositivo del receptor tiene la clave para descifrarlo. El servidor que lo transporta (y cualquiera que espíe la red) solo ve bytes cifrados.

- **Protege:** la **confidencialidad** del contenido (nadie en el camino lo lee, ni siquiera el proveedor) y su **integridad** (si alguien cambia un byte, el receptor lo detecta y lo rechaza).
- **No protege:** los **metadatos** (quién habla con quién, cuándo, cuánto, desde qué IP), los **dispositivos** (si roban o infectan el teléfono, el atacante lee los mensajes ya descifrados), las **copias de seguridad** que no estén cifradas, ni al usuario frente a una **suplantación** si no verifica la identidad del contacto (número de seguridad).

## Amenaza

**¿Qué es el secreto hacia adelante (forward secrecy) y qué amenaza mitiga?**
Forward secrecy significa que **si hoy se roba la clave (o el estado completo) de un participante, los mensajes del pasado siguen protegidos.**

La amenaza es "grabar ahora, descifrar después": un atacante guarda todo el tráfico cifrado durante meses y luego compromete el dispositivo. Si siempre se usara la misma clave, con ella abriría todo el historial. Con forward secrecy, cada mensaje usa una clave que se borra después de usarla y que no se puede recalcular a partir del estado actual.

Una propiedad complementaria es la **seguridad post-compromiso** (*post-compromise security*, también llamada "auto-curación"): después de un robo, en cuanto las partes hacen un nuevo intercambio Diffie-Hellman, el atacante pierde el acceso a los mensajes **futuros**.

## Mecanismo

**¿Cómo logra Signal esa propiedad con su cadena de claves?**
Signal usa el algoritmo **Double Ratchet** ("doble trinquete"; un trinquete solo gira hacia un lado):

1. **Trinquete simétrico (cadena de claves).** De una *clave de cadena* se derivan, con una función KDF de un solo sentido (HMAC/HKDF), dos cosas: la *clave del mensaje* y la *siguiente clave de cadena*. La clave del mensaje se usa una vez y se borra; la cadena vieja se sobrescribe. Como la KDF no se puede invertir, quien robe la cadena actual no puede volver a las claves anteriores → **forward secrecy**.
2. **Trinquete Diffie-Hellman.** Cada vez que cambia el turno de la conversación, el que escribe genera un **par de claves efímero nuevo** (X25519) y envía su pública en la cabecera. El nuevo secreto DH se mezcla con la *clave raíz* para iniciar cadenas nuevas. Un atacante que tenía el estado viejo no conoce la nueva privada → **seguridad post-compromiso**.
3. El secreto inicial compartido sale del protocolo **X3DH**, y cada mensaje se cifra con un esquema AEAD (cifrado autenticado), que detecta alteraciones.

En este taller: A1 implementa el punto 1 y A2 implementa los puntos 1 y 2 de forma reducida.

## Fuentes

1. K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt y D. Stebila. "A Formal Security Analysis of the Signal Messaging Protocol". *IEEE European Symposium on Security and Privacy (EuroS&P)*, 2017, pp. 451-466. (Fuente primaria: prueba formal de forward secrecy y post-compromise security de Signal.)
2. T. Perrin y M. Marlinspike. "The Double Ratchet Algorithm". Especificación de Signal, revisión 1, 20 de noviembre de 2016. https://signal.org/docs/specifications/doubleratchet/ (Fuente primaria: especificación oficial.)
3. M. Marlinspike y T. Perrin. "The X3DH Key Agreement Protocol". Especificación de Signal, 2016. https://signal.org/docs/specifications/x3dh/
4. H. Krawczyk y P. Eronen. RFC 5869, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", IETF, 2010.
5. A. Langley, M. Hamburg y S. Turner. RFC 7748, "Elliptic Curves for Security" (X25519), IETF, 2016.
