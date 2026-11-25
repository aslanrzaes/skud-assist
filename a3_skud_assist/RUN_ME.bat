@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set SKUD_BACKEND=ollama
set SKUD_MODEL=qwen2.5:3b
set SKUD_FALLBACK_MODELS=qwen2.5:1.5b

echo === SKUD-Assist: Assignment 3 experiment ===
echo.
where python >nul 2>nul || (echo Python not found. Install Python 3.10+ from python.org and tick "Add to PATH". & pause & exit /b 1)
where ollama >nul 2>nul || (echo Ollama not found in PATH. Start the Ollama app and try again. & pause & exit /b 1)

echo [1/4] Creating virtual environment...
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat

echo [2/4] Installing packages (first run: 5-10 min)...
python -m pip install --upgrade pip -q
python -m pip install -q torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -q -r requirements.txt

echo [3/4] Downloading the models %SKUD_MODEL% and %SKUD_FALLBACK_MODELS% (first run: about 3 GB)...
ollama pull %SKUD_MODEL%
ollama pull %SKUD_FALLBACK_MODELS%

echo [4/4] Running the experiment (this can take 1-2 hours; you can minimise this window)...
python run_all.py
echo.
echo Finished. Tell Claude "done" - it will read the results folder.
pause
