"""
Archivo especial de pytest: se carga solo, antes de las pruebas.

pytest_sessionfinish se ejecuta UNA vez cuando terminan todas las pruebas,
y ahí se generan log_pruebas.json y resultados.csv.
"""

import registro


def pytest_sessionfinish(session, exitstatus):
    registro.guardar_archivos()
