@echo off
title SecuRAG AI - SOC Investigation Platform Launcher
color 0b

echo ===============================================================================
echo                SecuRAG AI - Local SOC Investigation Platform
echo ===============================================================================
echo [1/3] Checking Prerequisites...

:: Verify MariaDB/MySQL service
netstat -ano | findstr :3306 >nul
if %errorlevel% neq 0 (
    echo [!] Warning: Port 3306 does not appear to be active.
    echo     Please make sure XAMPP / MariaDB / MySQL is started.
) else (
    echo [*] MariaDB/MySQL detected on port 3306.
)

:: Verify Ollama
curl -s http://127.0.0.1:11434/api/tags >nul
if %errorlevel% neq 0 (
    echo [!] Warning: Ollama is not reachable on http://127.0.0.1:11434
    echo     Please start Ollama service.
) else (
    echo [*] Ollama service is online.
)

echo.
echo [2/3] Starting Flask Backend on http://127.0.0.1:5000 ...
start "SecuRAG Backend (Flask API)" cmd /k "cd backend && venv\Scripts\python.exe app.py"

echo [3/3] Starting React + Tailwind Frontend on http://localhost:5173 ...
start "SecuRAG Frontend (Vite React)" cmd /k "cd frontend && npm run dev"

echo.
echo [*] Waiting for services to initialize...
timeout /t 3 >nul

echo [*] Opening SecuRAG AI Dashboard in your browser...
start http://localhost:5173

echo.
echo ===============================================================================
echo  SecuRAG AI is now RUNNING!
echo   - Frontend: http://localhost:5173
echo   - Backend:  http://127.0.0.1:5000
echo   - MariaDB:  securag_db (localhost:3306)
echo   - VectorDB: ChromaDB (Local Embeddings: nomic-embed-text)
echo ===============================================================================
echo Keep the backend and frontend terminal windows open.
pause
