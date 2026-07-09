# Start llama-server with the uncensored model
# Prerequisites: Download model first from HuggingFace
#   huggingface-cli download HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ4_XS.gguf --local-dir models/

param(
    [int]$Port = 8080,
    [int]$Threads = 8,
    [int]$NCMOE = 32,
    [int]$ContextLength = 262144
)

$ModelPath = "models/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ4_XS.gguf"

if (-not (Test-Path $ModelPath)) {
    Write-Host "[!] Model not found at $ModelPath"
    Write-Host "[!] Download it from: https://huggingface.co/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive"
    Write-Host "[!] Place the IQ4_XS.gguf file in the models/ directory"
    exit 1
}

Write-Host "[+] Starting llama-server on port $Port..."
Write-Host "[+] Model: $ModelPath"
Write-Host "[+] Context: $ContextLength tokens"

llama-server `
    -m $ModelPath `
    --host 127.0.0.1 `
    --port $Port `
    -ngl 999 `
    -ncmoe $NCMOE `
    --no-mmap `
    -c $ContextLength `
    --cache-type-k q4_0 `
    --cache-type-v q4_0 `
    --flash-attn on `
    -t $Threads `
    -b 1024 `
    -ub 512
