param (
    [string]$Input,
    [string]$Output,
    [switch]$Help
)

function Show-Usage {
    Write-Host "Usage: .\extract_polyglot.ps1 -Input <polyglot_image> -Output <output_binary>"
    Write-Host ""
    Write-Host "Extract executable payload from polyglot image"
    exit 0
}

if ($Help -or -not $Input -or -not $Output) {
    Show-Usage
}

if (-not (Test-Path $Input)) {
    Write-Error "Input file not found: $Input"
    exit 1
}

Write-Host "[*] Analyzing polyglot: $Input"

$FileBytes = [System.IO.File]::ReadAllBytes($Input)
$Header = $FileBytes[0..7]

$Offset = 0

if ($Header[0] -eq 0xFF -and $Header[1] -eq 0xD8) {
    Write-Host "[*] Detected JPEG polyglot"
    for ($i = 20; $i -lt $FileBytes.Length - 1; $i++) {
        if ($FileBytes[$i] -eq 0x4D -and $FileBytes[$i+1] -eq 0x5A) {
            $Offset = $i
            break
        }
    }
    if ($Offset -eq 0) {
        $Offset = 20
    }
} elseif ($Header[0] -eq 0x89 -and $Header[1] -eq 0x50 -and $Header[2] -eq 0x4E -and $Header[3] -eq 0x47) {
    Write-Host "[*] Detected PNG polyglot"
    for ($i = 8; $i -lt $FileBytes.Length - 1; $i++) {
        if ($FileBytes[$i] -eq 0x4D -and $FileBytes[$i+1] -eq 0x5A) {
            $Offset = $i
            break
        }
    }
    if ($Offset -eq 0) {
        $Offset = 8
    }
} elseif ($Header[0] -eq 0x42 -and $Header[1] -eq 0x4D) {
    Write-Host "[*] Detected BMP polyglot"
    for ($i = 54; $i -lt $FileBytes.Length - 1; $i++) {
        if ($FileBytes[$i] -eq 0x4D -and $FileBytes[$i+1] -eq 0x5A) {
            $Offset = $i
            break
        }
    }
    if ($Offset -eq 0) {
        $Offset = 54
    }
} else {
    Write-Host "[!] Unknown format, attempting to find PE header (MZ)"
    for ($i = 0; $i -lt $FileBytes.Length - 1; $i++) {
        if ($FileBytes[$i] -eq 0x4D -and $FileBytes[$i+1] -eq 0x5A) {
            $Offset = $i
            break
        }
    }
    if ($Offset -eq 0) {
        Write-Error "Could not find PE header"
        exit 1
    }
}

Write-Host "[*] Extracting payload from offset: $Offset"

$PayloadBytes = $FileBytes[$Offset..($FileBytes.Length - 1)]
[System.IO.File]::WriteAllBytes($Output, $PayloadBytes)

if (Test-Path $Output) {
    $ExtractedHeader = Get-Content $Output -Encoding Byte -TotalCount 2
    
    if ($ExtractedHeader[0] -eq 0x4D -and $ExtractedHeader[1] -eq 0x5A) {
        Write-Host "[+] Successfully extracted PE executable"
    } elseif ($ExtractedHeader[0] -eq 0x7F -and $ExtractedHeader[1] -eq 0x45) {
        Write-Host "[+] Successfully extracted ELF binary"
    } else {
        Write-Host "[!] Warning: Extracted file may not be a valid executable"
    }
    
    Write-Host "[+] Payload extracted to: $Output"
} else {
    Write-Error "Extraction failed"
    exit 1
}
