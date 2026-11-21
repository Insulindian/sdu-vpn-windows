@echo off
chcp 65001 >nul
cd /d "%~dp0.."
set "PYTHONPATH=%CD%\client"
python -m sdu_connect.app
if errorlevel 1 pause