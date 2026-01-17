# Fix line endings for all shell scripts in QuantumForge

Write-Host "Fixing line endings for shell scripts..." -ForegroundColor Cyan

$scripts = @(
    "/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge/compile_all.sh",
    "/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge/tests/test_loader_linux.sh",
    "/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge/tests/test_loader_mac.sh",
    "/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge/tests/run_tests_wsl.sh"
)

foreach ($script in $scripts) {
    Write-Host "  Fixing: $script"
    wsl sed -i 's/\r$//' $script
}

Write-Host "Line endings fixed!" -ForegroundColor Green
