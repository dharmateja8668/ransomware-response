@echo off
echo ============================================================
echo   ZAALIMA SOC Platform - Full Stack Startup
echo ============================================================
echo.
echo Starting Backend (FastAPI) and Frontend (Next.js)...
echo.

start "ZAALIMA Backend" cmd /k "cd /d d:\ransomware response\zaalima\backend && call venv\Scripts\activate && uvicorn main:app --reload --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

start "ZAALIMA Frontend" cmd /k "cd /d d:\ransomware response\zaalima\frontend && npm run dev"

echo.
echo [OK] Both servers starting...
echo     Backend:  http://localhost:8000
echo     Frontend: http://localhost:3000
echo     API Docs: http://localhost:8000/docs
echo.
pause

