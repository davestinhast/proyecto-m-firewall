"""
Punto de entrada principal del proyecto M-FIREWALL.
Ejecutar con: python run.py
"""

import sys
import os
import traceback

# Garantizar que el directorio raíz del proyecto esté en sys.path
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from app.main import main
except Exception as e:
    print("=" * 60)
    print("ERROR al importar la aplicación:")
    print(f"  {type(e).__name__}: {e}")
    print("")
    print("Traceback completo:")
    traceback.print_exc()
    print("=" * 60)
    print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', '(no definido)')}")
    print(f"sys.path[0]: {sys.path[0]}")
    print(f"Directorio de trabajo: {os.getcwd()}")
    print(f"Python: {sys.executable}")
    sys.exit(1)

if __name__ == "__main__":
    main()
