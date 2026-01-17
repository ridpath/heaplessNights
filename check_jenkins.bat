@echo off
wsl -d parrot bash -c "curl -s http://localhost:8080/pluginManager/api/json 2>/dev/null | head -c 500"
