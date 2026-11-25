@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set MLFLOW_DISABLE_AGENT_HINT=1
echo === SKUD-Assist: Assignment 4 monitoring (offline replay of A3 traces) ===
where python >nul 2>nul || (echo Python not found. & pause & exit /b 1)
if exist ..\.venv\Scripts\activate.bat (
  call ..\.venv\Scripts\activate.bat
) else (
  if not exist .venv python -m venv .venv
  call .venv\Scripts\activate.bat
)
echo [1/3] Installing MLflow (first run: 2-5 min)...
python -m pip install -q -r requirements.txt
echo [2/3] Replaying 210 recorded requests through the monitor (about 30 s)...
if exist mlflow.db del mlflow.db
python a4_monitor.py
echo [3/3] Opening the MLflow UI at http://127.0.0.1:5000  (close this window to stop it)
start "" http://127.0.0.1:5000
mlflow ui --backend-store-uri sqlite:///mlflow.db --port 5000
