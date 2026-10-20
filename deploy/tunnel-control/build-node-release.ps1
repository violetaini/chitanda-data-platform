$ErrorActionPreference = 'Stop'
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$releaseDirectory = Join-Path $workspaceRoot 'tmp/node-release'
New-Item -ItemType Directory -Path $releaseDirectory -Force | Out-Null
$sourceText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'engine/main.go'))
$engineVersion = [regex]::Match($sourceText, 'const version = "([0-9.]+)"').Groups[1].Value
if (-not $engineVersion) { throw 'Engine version missing' }
$manifest = [ordered]@{ version = $engineVersion; assets = [ordered]@{} }
foreach ($architecture in @('amd64','arm64','armv7','386','riscv64','loong64','ppc64le','s390x')) {
    & (Join-Path $PSScriptRoot 'build-engine.ps1') -Architecture $architecture
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $architecture" }
    $name = "chitanda-transit-linux-$architecture"
    $target = Join-Path $releaseDirectory $name
    Copy-Item -LiteralPath (Join-Path $workspaceRoot "tmp/$name") -Destination $target
    $manifest.assets["linux-$architecture"] = [ordered]@{ file = $name; sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $target).Length }
}
[IO.File]::WriteAllText((Join-Path $releaseDirectory 'manifest.json'), ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
Write-Output "Built node $engineVersion for all configured Linux architectures in $releaseDirectory"
