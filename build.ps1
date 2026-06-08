# build.ps1
# Compile every Rue puzzle entry-point in this project to CLVM bytecode.
#
# For each entry-point .rue file in puzzles/, emits two files in
# puzzles/compiled/<relative-path>/:
#   <name>.rue.hex   — CLVM bytecode in hex
#   <name>.rue.hash  — puzzle tree hash in hex
#
# Library-only files (those without a `main` function) are skipped.

$ErrorActionPreference = "Stop"

# Library files (no `main` function — only types/helpers, imported by entry points).
$libraries = @(
    "puzzles/common_types.rue",
    "puzzles/finalizer.rue",
    "puzzles/merkle_utils.rue",
    "puzzles/poseidon.rue",
    "puzzles/election/shared.rue",
    "puzzles/registration_coin/shared.rue",
    "puzzles/ceremony_singleton/shared.rue"
)

# Find all .rue files under puzzles/, excluding the libraries above.
$rueFiles = Get-ChildItem -Path "puzzles" -Filter "*.rue" -Recurse |
    ForEach-Object { (Resolve-Path -Relative $_.FullName) -replace '\\', '/' } |
    ForEach-Object { $_ -replace '^\./', '' } |
    Where-Object { $libraries -notcontains $_ }

# Output directory mirrors the source layout under puzzles/compiled/.
$outRoot = "puzzles/compiled"
if (Test-Path $outRoot) {
    Remove-Item -Recurse -Force $outRoot
}
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

$failed = @()
$built = 0

foreach ($rueFile in $rueFiles) {
    # puzzles/foo/bar.rue → puzzles/compiled/foo/bar.rue.{hex,hash}
    $relPath = $rueFile -replace '^puzzles/', ''
    $relDir = Split-Path $relPath -Parent
    $outDir = if ($relDir) { Join-Path $outRoot $relDir } else { $outRoot }
    $baseName = Split-Path $relPath -Leaf
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    $hexPath = Join-Path $outDir ($baseName + ".hex")
    $hashPath = Join-Path $outDir ($baseName + ".hash")

    Write-Host "Building $rueFile" -ForegroundColor Cyan

    # rue build prints warnings to stderr; we only want stdout (the hex / hash).
    $hex = & rue build $rueFile --hex 2>$null | Out-String
    $hex = $hex.Trim()
    if ($LASTEXITCODE -ne 0 -or -not $hex) {
        Write-Host "  FAILED to build hex for $rueFile" -ForegroundColor Red
        $failed += $rueFile
        continue
    }
    $hash = & rue build $rueFile --hash 2>$null | Out-String
    $hash = $hash.Trim()
    if ($LASTEXITCODE -ne 0 -or -not $hash) {
        Write-Host "  FAILED to build hash for $rueFile" -ForegroundColor Red
        $failed += $rueFile
        continue
    }

    [System.IO.File]::WriteAllText($hexPath, $hex)
    [System.IO.File]::WriteAllText($hashPath, $hash)
    $built++
}

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed to build:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host ("Built {0} puzzle(s) into {1}/" -f $built, $outRoot) -ForegroundColor Green
