@echo off
cd /d "%~dp0"
echo.
echo  AWS Cloud Security Drift Detective - Local Test
echo  (No AWS account needed)
echo.
python scripts\local_test.py
pause
