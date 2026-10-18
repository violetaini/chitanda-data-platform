$ErrorActionPreference = 'Stop'
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sourcePath = Join-Path $workspaceRoot 'tmp/chitanda-tunnel-core'
if (-not (Test-Path -LiteralPath $sourcePath)) {
    git clone https://github.com/chitanda-project/chitanda.git $sourcePath
    if ($LASTEXITCODE -ne 0) { throw 'Unable to retrieve Chitanda source' }
}
git -C $sourcePath checkout 2926cf2c41c85d2177536a4ba2d9931f1ec675f9
if ($LASTEXITCODE -ne 0) { throw 'Unable to pin Chitanda source' }
$destinationPath = Join-Path $sourcePath 'cmd/chitanda-transit'
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'engine') -Filter '*.go' -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destinationPath $_.Name) }
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
Push-Location $sourcePath
try {
    go build -mod=mod -trimpath -ldflags '-s -w' -o (Join-Path $workspaceRoot 'tmp/chitanda-transit') ./cmd/chitanda-transit
    if ($LASTEXITCODE -ne 0) { throw 'Engine build failed' }
} finally { Pop-Location }
