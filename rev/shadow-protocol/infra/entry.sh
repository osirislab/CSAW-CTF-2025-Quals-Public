#!/bin/sh
# /app/entry.sh
stdbuf -o0 -e0 /app/shadow_protocol 2>&1
printf "\nPress ENTER to exit..."
read _ || true
