param([ValidateSet('amd64','arm64','armv7','386','riscv64','loong64','ppc64le','s390x')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
$security = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'go-security.json') -Raw | ConvertFrom-Json
if ($security.toolchain -notmatch '^go[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Invalid pinned Go toolchain' }
$env:GOTOOLCHAIN = $security.toolchain
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sourcePath = Join-Path $workspaceRoot 'tmp/chitanda-tunnel-core'
if (-not (Test-Path -LiteralPath $sourcePath)) {
    git clone https://github.com/chitanda-project/chitanda.git $sourcePath
    if ($LASTEXITCODE -ne 0) { throw 'Unable to retrieve Chitanda source' }
}
git -C $sourcePath checkout 2926cf2c41c85d2177536a4ba2d9931f1ec675f9
if ($LASTEXITCODE -ne 0) { throw 'Unable to pin Chitanda source' }
Get-ChildItem -LiteralPath (Join-Path $workspaceRoot 'patches') -Filter '*.patch' -File | Sort-Object Name | ForEach-Object {
    git -C $sourcePath apply --reverse --check $_.FullName 2>$null
    if ($LASTEXITCODE -ne 0) {
        git -C $sourcePath apply --check $_.FullName
        if ($LASTEXITCODE -ne 0) { throw 'Upstream does not match the reviewed telemetry patch' }
        git -C $sourcePath apply $_.FullName
        if ($LASTEXITCODE -ne 0) { throw 'Unable to apply TLS observation patch' }
    }
}
$destinationPath = Join-Path $sourcePath 'cmd/chitanda-transit'
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'engine') -Filter '*.go' -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destinationPath $_.Name) }
$env:GOOS = 'linux'
$env:GOARCH = if ($Architecture -eq 'armv7') { 'arm' } else { $Architecture }
$env:GOAMD64 = 'v1'
$env:GOARM64 = 'v8.0'
$env:GOARM = '6'
$env:GO386 = 'softfloat'
$env:CGO_ENABLED = '0'
Push-Location $sourcePath
try {
    foreach ($dependency in $security.modules.PSObject.Properties) {
        if ($dependency.Name -notmatch '^golang.org/x/[a-z]+$' -or $dependency.Value -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Invalid pinned Go dependency' }
        go mod edit "-require=$($dependency.Name)@$($dependency.Value)"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to pin security dependencies' }
    }
    $outputPath = Join-Path $workspaceRoot "tmp/chitanda-transit-linux-$Architecture"
    go build -mod=mod -trimpath -ldflags '-s -w' -o $outputPath ./cmd/chitanda-transit
    if ($LASTEXITCODE -ne 0) { throw 'Engine build failed' }
    if ($Architecture -eq 'amd64') { Copy-Item -LiteralPath $outputPath -Destination (Join-Path $workspaceRoot 'tmp/chitanda-transit') }
} finally { Pop-Location }
