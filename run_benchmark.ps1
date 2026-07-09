# Run model benchmark to determine optimal settings
# Requires llama-server running on port 8080 with model loaded

Write-Host "[+] Running model benchmark..."
Write-Host "[!] Make sure llama-server is running first (start_server.ps1)"

python -m src.main benchmark

Write-Host "[+] Check config.yaml for updated {AUTO} values"
