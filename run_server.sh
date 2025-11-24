#!/usr/bin/env zsh
# Lightweight helper to run the Dory-Lat Flask app using the repo venv if available.
# Usage:
#   ./run_server.sh [-h host] [-p port] [-g] [-b] [-d]
# Options:
#   -h host     Host to bind (default 0.0.0.0)
#   -p port     Port to use (default 5000)
#   -g          Use gunicorn from venv if available
#   -b          Run in background (logs to server.log)
#   -d          Enable Flask debug (when running with python)

set -euo pipefail

VENV_DIR="./venv_hf"
PY_IN_VENV="$VENV_DIR/bin/python"
GUNICORN_IN_VENV="$VENV_DIR/bin/gunicorn"

HOST="0.0.0.0"
PORT="5000"
USE_GUNICORN=false
BACKGROUND=false
DEBUG=false

usage() {
  echo "Usage: $0 [-h host] [-p port] [-g] [-b] [-d]"
  echo "  -g use gunicorn from venv if available"
  echo "  -b background (nohup -> server.log)"
  echo "  -d debug mode (when using python)"
  exit 1
}

while getopts ":h:p:gbd" opt; do
  case $opt in
    h) HOST=$OPTARG ;;
    p) PORT=$OPTARG ;;
    g) USE_GUNICORN=true ;;
    b) BACKGROUND=true ;;
    d) DEBUG=true ;;
    *) usage ;;
  esac
done

# Determine python executable
if [ -x "$PY_IN_VENV" ]; then
  PY_EXEC="$PY_IN_VENV"
else
  if command -v python3 >/dev/null 2>&1; then
    PY_EXEC=$(command -v python3)
  elif command -v python >/dev/null 2>&1; then
    PY_EXEC=$(command -v python)
  else
    echo "No Python executable found. Please install Python or create ./venv_hf." >&2
    exit 1
  fi
fi

# Export commonly useful env vars
export PYTHONUNBUFFERED=1
export PORT="$PORT"

# Build command
if [ "$USE_GUNICORN" = true ] && [ -x "$GUNICORN_IN_VENV" ]; then
  echo "Starting with gunicorn from venv: $GUNICORN_IN_VENV"
  CMD=("$GUNICORN_IN_VENV" "app_hf:app" "--bind" "$HOST:$PORT" "--workers" "1")
else
  if [ "$DEBUG" = true ]; then
    export FLASK_ENV=development
    export FLASK_DEBUG=1
  fi
  CMD=("$PY_EXEC" "app_hf.py")
fi

# Start server
if [ "$BACKGROUND" = true ]; then
  echo "Starting server in background (logs -> server.log)"
  nohup "${CMD[@]}" > server.log 2>&1 &
  echo "Started PID: $!"
  echo "Tail logs with: tail -f server.log"
else
  echo "Starting server in foreground (host=$HOST port=$PORT)"
  exec "${CMD[@]}"
fi
