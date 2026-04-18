#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "  BlindSpot requer privilégios de administrador."
    echo "  Execute com: sudo ./run.sh"
    echo ""
    exit 1
fi

python3 blindspot.py