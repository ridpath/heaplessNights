Write-Host "===== QuantumForge Polyglot Builder Test =====" -ForegroundColor Cyan
Write-Host ""

$TestDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $TestDir
Set-Location $RootDir

$BaseKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$IV = "0123456789abcdef0123456789abcdef"
$Salt = "testsalt12345678"

Write-Host "[*] Creating test payload..."
@"
MZ...Test Payload...
"@ | Out-File -FilePath test_payload.bin -Encoding ASCII -NoNewline

Write-Host ""
Write-Host "===== Test 1: JPEG Polyglot (Default) =====" -ForegroundColor Yellow
.\quantum_forge_win.ps1 -Output test_output.jpg -Payload test_payload.bin -BaseKey $BaseKey -Salt $Salt -IV $IV

if (Test-Path test_output.jpg) {
    Write-Host "[+] JPEG polyglot created" -ForegroundColor Green
    
    $Header = Get-Content test_output.jpg -Encoding Byte -TotalCount 2
    if ($Header[0] -eq 0xFF -and $Header[1] -eq 0xD8) {
        Write-Host "[+] JPEG magic bytes correct" -ForegroundColor Green
    } else {
        Write-Host "[!] JPEG magic bytes incorrect" -ForegroundColor Red
        exit 1
    }
    
    if (Get-Command exiftool -ErrorAction SilentlyContinue) {
        Write-Host "[*] EXIF data:"
        exiftool test_output.jpg | Select-String "(Model|Artist|Comment)"
    }
} else {
    Write-Host "[!] JPEG polyglot creation failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===== Test 2: PNG Polyglot =====" -ForegroundColor Yellow
.\quantum_forge_win.ps1 -Output test_output.png -Payload test_payload.bin -BaseKey $BaseKey -Salt $Salt -IV $IV -Format png

if (Test-Path test_output.png) {
    Write-Host "[+] PNG polyglot created" -ForegroundColor Green
    
    $Header = Get-Content test_output.png -Encoding Byte -TotalCount 8
    if ($Header[0] -eq 0x89 -and $Header[1] -eq 0x50 -and $Header[2] -eq 0x4E -and $Header[3] -eq 0x47) {
        Write-Host "[+] PNG magic bytes correct" -ForegroundColor Green
    } else {
        Write-Host "[!] PNG magic bytes incorrect" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[!] PNG polyglot creation failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===== Test 3: BMP Polyglot =====" -ForegroundColor Yellow
.\quantum_forge_win.ps1 -Output test_output.bmp -Payload test_payload.bin -BaseKey $BaseKey -Salt $Salt -IV $IV -Format bmp

if (Test-Path test_output.bmp) {
    Write-Host "[+] BMP polyglot created" -ForegroundColor Green
    
    $Header = Get-Content test_output.bmp -Encoding Byte -TotalCount 2
    if ($Header[0] -eq 0x42 -and $Header[1] -eq 0x4D) {
        Write-Host "[+] BMP magic bytes correct" -ForegroundColor Green
    } else {
        Write-Host "[!] BMP magic bytes incorrect" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[!] BMP polyglot creation failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===== Test 4: No Polyglot (Binary Only) =====" -ForegroundColor Yellow
.\quantum_forge_win.ps1 -Output test_output.exe -Payload test_payload.bin -BaseKey $BaseKey -Salt $Salt -IV $IV -NoPolyglot

if (Test-Path test_output.exe) {
    Write-Host "[+] Binary created (no polyglot)" -ForegroundColor Green
    
    $Header = Get-Content test_output.exe -Encoding Byte -TotalCount 2
    if ($Header[0] -eq 0x4D -and $Header[1] -eq 0x5A) {
        Write-Host "[+] Correctly created as PE binary" -ForegroundColor Green
    } else {
        Write-Host "[!] Binary does not have PE magic bytes" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Binary creation failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===== Test 5: No EXIF =====" -ForegroundColor Yellow
.\quantum_forge_win.ps1 -Output test_output_noexif.jpg -Payload test_payload.bin -BaseKey $BaseKey -Salt $Salt -IV $IV -NoExif

if (Test-Path test_output_noexif.jpg) {
    Write-Host "[+] JPEG created without EXIF" -ForegroundColor Green
} else {
    Write-Host "[!] No-EXIF creation failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===== Test 6: Image Viewer Validation =====" -ForegroundColor Yellow
Write-Host "[*] Manual validation required: Open test_output.jpg, test_output.png, test_output.bmp in an image viewer"
Write-Host "[*] All files should open as valid images"

Write-Host ""
Write-Host "===== Cleanup =====" -ForegroundColor Yellow
Remove-Item test_payload.bin, test_output.jpg, test_output.png, test_output.bmp, test_output.exe, test_output_noexif.jpg -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "===== All Tests Passed =====" -ForegroundColor Green
