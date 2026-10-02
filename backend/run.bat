@echo off
title SecuRAG AI - Backend Server
cd %~dp0
echo Starting SecuRAG Backend on http://127.0.0.1:5000...
venv\Scripts\python.exe app.py
pause
