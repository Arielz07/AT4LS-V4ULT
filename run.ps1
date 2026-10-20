$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (!(Test-Path $VenvPython)) {
  Write-Host "Creating local virtual environment..."
  if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -m venv .venv
  } else {
    & python -m venv .venv
  }
  & $VenvPython -m pip install --upgrade pip
  & $VenvPython -m pip install -e .
}

& $VenvPython -c "import fastapi, uvicorn, jinja2, multipart, cryptography" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Installing project dependencies..."
  & $VenvPython -m pip install -e .
}

$BindHost = if ($env:ATL4S_HOST) { $env:ATL4S_HOST } else { "127.0.0.1" }
$BindPort = if ($env:ATL4S_PORT) { $env:ATL4S_PORT } else { "8000" }

Write-Host "ATL4S::V4UlT  http://${BindHost}:${BindPort}"
& $VenvPython -m uvicorn atl4s.main:app --host $BindHost --port $BindPort
