@echo off
echo ============================================================
echo   ZAALIMA SOC Platform - Backend Startup
echo ============================================================
echo.

cd /d "%~dp0"

if exist "venv\Scripts\activate" (
    call venv\Scripts\activate
) else if exist "..\..\venv\Scripts\activate" (
    call ..\..\venv\Scripts\activate
) else (
    echo [ERROR] Virtual environment not found. Run: python -m venv venv
    pause
    exit /b 1
)

echo [*] Checking PostgreSQL connection...
echo [*] Starting FastAPI backend on http://localhost:8000
echo [*] API docs available at http://localhost:8000/docs
echo.

uvicorn main:app --reload --host 0.0.0.0 --port 8000

