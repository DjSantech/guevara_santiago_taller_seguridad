# Taller individual: seguridad en Messenger

Santiago Guevara. Sistemas Distribuidos, noviembre de 2026.

Implementación simplificada de una cadena de claves (A1) y de un Double Ratchet reducido (A2), con pruebas automáticas.

## Instalar dependencias

Requiere Python 3.11 o más reciente.

```bash
python -m pip install cryptography pytest
```

## Ejecutar las pruebas (un solo comando)

```bash
python -m pytest -q
```

Salida esperada: `9 passed`. Al terminar se generan (o se sobrescriben):

- `resultados.csv`: la plantilla del taller con `obtenido`, `estado` y `comentario` llenos.
- `log_pruebas.json`: una entrada por prueba (`prueba`, `esperado`, `obtenido`, `estado`).

## Demostración opcional

```bash
python a2_ratchet.py
```

Muestra los 6 mensajes y cómo la clave pública cambia cuando cambia la dirección.

## Archivos

| Archivo | Qué contiene |
|---|---|
| `ficha.md` | Investigación: E2EE, forward secrecy y Double Ratchet |
| `a1_cadena.py` | A1: `derivar_clave`, `cifrar`, `descifrar`, `CadenaDeClaves` |
| `a2_ratchet.py` | A2: clase `Ratchet` (`enviar`, `recibir`, `cambiar_direccion`) |
| `test_a1.py`, `test_a2.py` | Una función por fila de resultados (`test_A1_01` …) |
| `registro.py`, `conftest.py` | Necesarios para las pruebas: guardan `resultados.csv` y `log_pruebas.json` |
| `informe.md` | Qué se implementó, diferencias con Signal y limitaciones |
