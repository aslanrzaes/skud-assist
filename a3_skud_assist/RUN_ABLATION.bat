@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set SKUD_BACKEND=ollama
set SKUD_MODEL=qwen2.5:3b
set SKUD_FALLBACK_MODELS=qwen2.5:1.5b
call .venv\Scripts\activate.bat
echo === SKUD-Assist: ablation run (about 15-20 min) ===
python run_ablation.py
pause
