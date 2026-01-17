@echo off
wsl -d parrot bash -c "cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker/jenkins-lab; dos2unix COMPLETE_TEST_SUITE.sh 2>/dev/null || sed -i 's/\r$//' COMPLETE_TEST_SUITE.sh || true"
