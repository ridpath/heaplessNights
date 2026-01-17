@echo off
wsl -d parrot bash -c "cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker; python3 -m pip install rich requests pyyaml colorama tabulate --break-system-packages"
