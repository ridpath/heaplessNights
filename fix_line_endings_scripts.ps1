# Fix line endings for all shell scripts
$scriptsPath = "C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\JenkinsBreaker\jenkins-lab\scripts"

Write-Host "[*] Fixing line endings for shell scripts in: $scriptsPath" -ForegroundColor Cyan

Get-ChildItem -Path "$scriptsPath\*.sh" | ForEach-Object {
    Write-Host "    Processing: $($_.Name)" -ForegroundColor Gray
    $content = Get-Content $_.FullName -Raw
    $content = $content -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($_.FullName, $content)
}

Write-Host "[+] Fixed line endings for all .sh files" -ForegroundColor Green
