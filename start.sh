#!/bin/bash

echo "========================================================"
echo
echo " ▗▄▄▖▗▖  ▗▖▗▄▄▖ ▗▄▄▄▖▗▄▄▖ ▗▄▄▖ ▗▖ ▗▖▗▖  ▗▖"
echo "▐▌    ▝▚▞▘ ▐▌ ▐▌▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ▝▚▞▘ "
echo "▐▌     ▐▌  ▐▛▀▚▖▐▛▀▀▘▐▛▀▚▖▐▛▀▘ ▐▛▀▜▌  ▐▌  "
echo "▝▚▄▄▖  ▐▌  ▐▙▄▞▘▐▙▄▄▖▐▌ ▐▌▐▌   ▐▌ ▐▌  ▐▌  "
echo "                                           "
echo "                                           "
echo "========================================================"
echo "                                           "

if [ ! -d ".env" ]; then
    python3 -m venv .env
    .env/bin/pip install -r requirements.txt
fi

.env/bin/python3 app.py
