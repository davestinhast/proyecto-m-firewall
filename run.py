"""
Punto de entrada principal del proyecto M-FIREWALL.
Ejecutar con: python run.py
"""

import sys
import os

# Agregar el directorio del proyecto al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import main

if __name__ == "__main__":
    main()
