param(
    [Parameter(Mandatory=$true)]
    [string]$RepoPath,
    [switch]$Resume
)

$resumeFlag = if ($Resume) { "--resume" } else { "" }

Write-Host "[+] Auditing: $RepoPath"

python -m src.main audit $RepoPath $resumeFlag
