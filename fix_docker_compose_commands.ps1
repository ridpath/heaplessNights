# Fix all docker-compose commands to support both v1 and v2

$scriptsPath = "C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\JenkinsBreaker\jenkins-lab\scripts"

$files = @(
    "verify_secrets.sh",
    "run_full_test_cycle.sh",
    "test_exploits_production.sh"
)

foreach ($file in $files) {
    $filePath = Join-Path $scriptsPath $file
    if (Test-Path $filePath) {
        Write-Host "Processing: $file" -ForegroundColor Cyan
        $content = Get-Content $filePath -Raw
        
        # Add compose detection if not already present
        if ($content -notmatch 'COMPOSE_CMD=') {
            # Find the first docker-compose command
            if ($content -match 'docker-compose') {
                # Add detection after shebang and set -e
                $content = $content -replace '(set -e\s*\n)', "`$1`n# Detect Docker Compose command`nif docker compose version &> /dev/null 2>&1; then`n    COMPOSE_CMD=`"docker compose`"`nelif command -v docker-compose &> /dev/null; then`n    COMPOSE_CMD=`"docker-compose`"`nelse`n    COMPOSE_CMD=`"docker-compose`"`nfi`n"
                
                # Replace all docker-compose with $COMPOSE_CMD
                $content = $content -replace '(?<!COMPOSE_CMD=")docker-compose', '`$COMPOSE_CMD'
                
                [System.IO.File]::WriteAllText($filePath, $content)
                Write-Host "  Updated: $file" -ForegroundColor Green
            }
        }
    }
}

Write-Host "`n[+] All scripts updated!" -ForegroundColor Green
