@echo off
wsl -d parrot bash -c "cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker/jenkins-lab; sed -i 's/\r$//' PRODUCTION_READINESS_CHECK.sh; bash PRODUCTION_READINESS_CHECK.sh"
