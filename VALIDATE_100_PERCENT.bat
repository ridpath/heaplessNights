@echo off
echo ==========================================
echo   JenkinsBreaker 100%% Validation Check
echo ==========================================
echo.
echo Running production readiness validation...
echo.
wsl -d parrot bash -c "cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker/jenkins-lab; sed -i 's/\r$//' PRODUCTION_READINESS_CHECK.sh 2>/dev/null; bash PRODUCTION_READINESS_CHECK.sh"
echo.
echo ==========================================
echo   Validation Complete
echo ==========================================
pause
