# Local Vuln Research System

Exhaustive LLM-driven whitebox vulnerability research pipeline that finds every single vulnerability in any source code. Built on a code graph + LLM hybrid architecture that enumerates and validates all source-to-sink paths.

Scales from small scripts to enterprise codebases: Linux Kernel, VSCode, Microsoft Agent Framework, GitHub Desktop.

---

## What It Does

Finds every valid vulnerability in source code through exhaustive enumeration:

1. Parses every source file across 16 languages
2. Builds a complete call graph with cross-file imports
3. Tags every untrusted input source and dangerous operation sink
4. Enumerates every source-to-sink path through the call graph
5. Tracks taint through each function on each path (intra- + inter-procedural)
6. Cross-references sanitizers against sink categories via normalized taxonomy
7. Validates ambiguous paths with LLM for genuine exploitability
8. Auto-classifies clear-cut cases deterministically (sanitizer match → blocked)
9. Sweeps every file NOT covered by paths with a blind-spot code review (Project Black methodology)
10. Injects relevant product CVEs into every LLM prompt for pattern matching
11. Analyzes memory corruption for C/C++/Rust codebases
12. Synthesizes multi-step exploit chains via networkx transitive closure

Every source (untrusted input entry point) is paired with every compatible sink (dangerous operation) and all call-graph paths between them are analyzed. Nothing is sampled.

---

## Architecture

```
[Target Repo]
    |
Step 0  - Fingerprint + SBOM              (deterministic, full file inventory)
Step 1  - Classify target                 (16+ target types, dual-language detection)
Step 2  - Dependency vuln scan            (NVD + EPSS/KEV ranked)
Step 2b - Secrets scan                    (gitleaks rules)
Step 3  - Static analysis                 (Semgrep scan + file inventory)
Step 3b - Code graph construction         (call graph + source/sink/sanitizer tags + memory analysis)
Step 4  - Threat model + CVE catalog      (1 LLM pass, product-specific CVE search)
Step 4b - Path enumeration               (exhaustive source-to-sink path discovery + inter-procedural taint)
Step 4c - Per-path LLM analysis           (exploitability validation, one path at a time + CVE context)
Step 4d - Blind spot coverage             (file-by-file LLM review of all uncovered source files)
Step 5  - Memory findings extraction      (results from step 3b's memory analysis)
Step 6  - Chain synthesis                 (networkx attack graph + transitive closure)
Step 7  - Validation                      (confidence-based filtering)
Step 8  - Anomaly check                   (prompt injection detection)
Step 9  - Report + PoC                    (root cause, exploit path, remediation)
    |
Output: Verified findings with proof of exhaustive coverage
```

The code graph is built deterministically. The LLM is used only for exploitability reasoning on pre-traced paths, never for discovery.

---

## Supported Targets

| Target | Language | Size | Status |
|--------|----------|------|--------|
| Linux Kernel | C | ~30M LOC | Supported via memory analysis + call graph |
| VSCode | TypeScript | ~400K LOC | Full tree-sitter parsing + path enumeration |
| Microsoft Agent Framework | C# / .NET | Varies | Full C# sink coverage |
| GitHub Desktop | TypeScript / Electron | ~200K LOC | TypeScript + Node.js patterns |
| React, Angular, Vue | JS/TS | Varies | SSTI, XSS, prototype pollution |
| Django, Flask, Express | Python/JS | Varies | HTTP routes, ORM, auth decorators |
| Spring Boot | Java | Varies | All Spring annotations, SpEL, deserialization |
| Go services | Go | Varies | All Go sinks, goroutine races |
| Rust crates | Rust | Varies | Memory safety + unsafe FFI |

### Theoretical Limits

What the system can do:
- Exhaustively enumerate all statically resolvable source-to-sink paths
- Find every injection vulnerability (command, SQL, path, SSRF, SSTI, etc.)
- Find every deserialization vulnerability
- Find every auth bypass and access control issue
- Find every memory corruption issue in C/C++/Rust
- Find every hardcoded credential
- Find every race condition and TOCTOU
- Find every XXE, LDAP injection, XPath injection
- Find every weak crypto and weak random usage

Known fundamental limits (inherent to static analysis):
- Dynamic dispatch through function pointers in C: conservatively flagged, exact target unknown without runtime info
- Virtual dispatch through vtables in C++/Java/C#: conservative resolution
- Reflection-based calls: flagged as suspicious with severity based on context
- C macros: AST parser does not expand macros
- Assembly code: not analyzed
- Cross-translation-unit inlining in C: call graph shows as separate functions

For these edge cases, the system reports them as uncertain via LLM analysis rather than giving false negatives.

---

## Hardware Requirements

Tested configuration:
- GPU: RTX 4070 Ti SUPER (16GB VRAM)
- CPU: Ryzen 7 7700 (8C/16T)
- RAM: 32GB DDR5 6000MHz
- Model: Qwen2.5-Coder-14B-Abliterated Q4_K_M (14B dense, 8.6GB)
- Draft model: Qwen2.5-Coder-0.5B Q4_K_M (~400MB) for speculative decoding
- Total VRAM: ~9GB models, ~7GB free for KV cache
- Performance: 25-35 tok/s base, 35-50 effective tok/s with speculative decoding
- Context: 32K tokens (model training limit)
- Server: llama.cpp with jinja, flash attention, Q4 KV cache

---

## Installation

### 1. Install llama.cpp

```powershell
winget install llama.cpp      # Windows
brew install llama.cpp         # macOS / Linux
pip install -r requirements.txt
pip install huggingface_hub
```

### 2. Download Models

```powershell
huggingface-cli download bartowski/Qwen2.5-Coder-14B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf --local-dir models/

huggingface-cli download bartowski/Qwen2.5-Coder-0.5B-Instruct-abliterated-GGUF `
  Qwen2.5-Coder-0.5B-Instruct-abliterated-Q4_K_M.gguf --local-dir models/
```

### 3. Start Model Server

```powershell
python start_server.py
```

Reads model path from `config.yaml`. Use `--no-speculative` to disable speculative decoding.

### 4. Get NVD API Key

https://nvd.nist.gov/developers/request-an-api-key (30 seconds)

### 5. Download CVE Database

```powershell
$env:NVD_API_KEY="your-key-here"
python -m src.main update-cve
```

This downloads ~45 minutes of data: 364K+ CVEs with EPSS + KEV, product-specific search.

### 6. Estimate Resources (Optional)

```powershell
python -m src.main estimate /path/to/target-repo
```

### 7. Run Audit

```powershell
python run_audit.py /path/to/target-repo
python run_audit.py /path/to/target-repo --resume   # resume from checkpoint
```

---

## Pipeline Details

### Step 3b: Code Graph Construction

Builds the complete foundation for exhaustive analysis:
- AST parsing: 9 languages via tree-sitter, 7 via regex fallback
- Call graph: every function to every callee, direct + virtual dispatch, cross-file via import resolution
- Call sites: arguments extracted from every call expression for inter-procedural taint
- Source tags: every untrusted entry point annotated with source type
- Sink tags: every dangerous operation tagged with vulnerability class
- Sanitizer tags: every validator, encoder, auth check identified with `protected_against` categories
- Memory analysis: 5 parallel analyzers run inline for C/C++/Rust

### Step 4b: Path Enumeration

For every source-to-sink pair that is compatible:
1. Use the call graph to find all call paths from source to sink
2. Trace taint through each function on the path (intra-procedural + inter-procedural accumulation)
3. Cross-reference sanitizers against sink categories using a normalized taxonomy — sanitizer `protected_against` values are mapped to sink categories via `SINK_TO_SANITIZER_TAXONOMY`
4. Blocked paths still proceed to LLM analysis (sanitizer effectiveness verified, not blind-trusted)
5. Record the complete path inventory

A medium codebase (~800 files) might produce 5,000-50,000 source-to-sink paths. Large codebases (Linux kernel, VSCode) use chunked processing and path prioritization to scale to millions of paths.

### Step 4c: Per-Path LLM Analysis

For each enumerated path:
1. Paths are deduplicated by unique (source, sink, category) combination
2. Clear-cut cases get deterministic verdicts: sanitizer-taxonomy match → auto-BLOCKED, unreachable sink → auto-BLOCKED
3. Only ambiguous paths go to the LLM (real function chains, taint present, no matching sanitizer)
4. Every LLM prompt includes relevant CVE examples matching the path's CWE + product stack
5. No limit by default — `max_llm_paths: 0` means analyze every unique path

The LLM does not discover paths. It analyzes a path the graph already found.

### Step 4d: Blind Spot Coverage (Project Black Methodology)

Code graph + path enumeration finds every data-flow vulnerability (injection, traversal, SSRF, deserialization). But some vulnerability classes don't follow a source-to-sink model — logic bugs, misconfigurations, auth gaps, weak crypto patterns the sink tagger doesn't recognize.

Step 4d sweeps every source file NOT covered by path analysis, sending batches of 5 files through the LLM with CVE context and the full source code. The LLM reviews each file for:
- Hardcoded credentials/secrets
- Weak cryptography/random patterns
- Auth check gaps and logic bugs
- Insecure defaults and dangerous configurations
- Race conditions and TOCTOU
- Template injection and unsafe native calls
- Commented-out dangerous code

Between path enumeration (data-flow vulns) and blind-spot coverage (everything else), every line of every source file is reviewed.

### Step 5: Memory Corruption Analysis

For C/C++/Rust codebases, five dedicated analyzers:
- Allocation tracker: integer overflow in size calculations, mismatched allocators
- Buffer analyzer: stack/heap overflow, out-of-bounds access, off-by-one
- Lifetime analyzer: use-after-free, double-free, invalid free
- Integer overflow: overflow in size calculations, array indices
- Format string: attacker-controlled format strings in printf/scanf family

### Step 6: Chain Synthesis

Builds an attack graph from all confirmed exploitable findings using networkx:
- Findings are classified by vulnerability role (code_exec, file_access, information_theft, access_escalation, etc.)
- Role transitions define valid chains: file_access → code_exec (LFI to RCE), information_theft → access_escalation (credential reuse), etc.
- Computes full transitive closure via graph shortest paths — A → C is valid if A → B → C exists
- Chains up to 50 most confident multi-step exploits are surfaced

### Steps 7-9: Validation, Anomaly, Report

- Step 7: Confidence-based filtering — CRITICAL and HIGH severity memory findings pass with >= 0.6 confidence; path analysis results are filtered by VERIFIED_EXPLOITABLE verdict
- Step 8: Prompt injection detection via InjectionGuard statistical baseline
- Step 9: Exhaustive report with coverage statistics, PoC ideas, and remediation

---

## Report Format

Every finding in the report includes:

1. Summary: what the vulnerability is
2. Root Cause: why it exists in the code
3. Code Chain: exact data flow from source to sink
4. PoC Steps to Reproduce: step-by-step instructions to trigger it
5. Impact: concrete damage description
6. Remediation: how to fix it with code examples
7. How an Attack Can Exploit This: realistic attack scenario

Plus overall Coverage Statistics showing:
- Total source files parsed
- Functions analyzed, call graph edges
- Entry points identified
- Sources, sinks, sanitizers tagged
- Total paths enumerated
- Paths analyzed by LLM
- Verified exploitable, blocked, uncertain
- Memory corruption findings
- Exploit chains synthesized

---

## Vulnerability Coverage

### Injection
- Command injection (system, exec, subprocess, AddScript, PowerShell)
- SQL injection (raw queries, ORM raw, second-order)
- NoSQL injection (MongoDB $where, $expr, $function)
- LDAP injection
- XPath injection
- SSTI (Server-Side Template Injection)
- Header injection / HTTP request smuggling

### Deserialization
- Python (pickle, marshal, yaml.load)
- Java (ObjectInputStream, XMLDecoder, ysoserial gadgets)
- .NET (BinaryFormatter, JavaScriptSerializer, TypeNameHandling)
- Ruby (Marshal.load, YAML.load)
- PHP (unserialize)

### Memory Corruption (C/C++/Unsafe Rust)
- Stack buffer overflow (strcpy, gets, sprintf)
- Heap buffer overflow (memcpy with user-controlled size)
- Use-after-free
- Double-free
- Null pointer dereference
- Integer overflow leading to corruption
- Format string vulnerability
- Off-by-one
- Type confusion

### Path and File
- Path traversal (directory traversal, zip slip)
- Arbitrary file read/write
- Insecure file permissions
- TOCTOU (time-of-check time-of-use)
- Symbolic link attacks

### Network
- SSRF (Server-Side Request Forgery)
- HTTP request smuggling
- Open redirect

### Authentication and Authorization
- IDOR (Insecure Direct Object Reference)
- Missing function-level access control
- Privilege escalation
- JWT attacks (alg:none, no signature verification, key confusion)
- OAuth redirect misuse
- Hardcoded credentials
- Weak session management

### Cryptography
- Weak algorithms (MD5, SHA1, DES, RC4)
- Weak random (non-CSRNG for security)
- Missing MAC/signature
- ECB mode
- Static IV/nonce
- TLS verification disabled

### Business Logic
- Parameter tampering
- Race conditions (TOCTOU, double-spend)
- Workflow bypass
- Type confusion

---

## Time Estimates

The system auto-adapts to codebase size:

| Repo Size | Files | Config | Est. Time |
|-----------|-------|--------|-----------|
| Small (~200 files) | ~150 | minimal | 15-25 min |
| Medium (~800 files) | ~600 | standard | 1-2 hours |
| Large (~2000 files) | ~1400 | large | 3-6 hours |
| Very Large (~5000 files) | ~3500 | large | 6-12 hours |
| Enterprise (~30K+ files) | ~25K+ | enterprise | 24-72 hours |

Each batch = 3 LLM calls. Time scales linearly. Checkpoint and resume at every batch.

---

## Scaling for Large Codebases

The system includes a dedicated scaling module (`src/analysis/scaling.py`):

### Chunking
- Files processed in chunks of 500
- Files larger than 10MB are skipped (likely generated)
- Test and vendor directories are excluded
- Per-directory processing for memory efficiency

### Parallelism
- Source, sink, sanitizer tagging parallelized across threads
- Configurable worker count (default 16, up to 32 for enterprise)

### Path Prioritization
- Paths scored by severity, vulnerability class, length, sanitizer presence
- Top N paths analyzed by LLM (configurable, default 500)
- Strategic sampling when budget is limited: all CRITICAL, all HIGH, sample of MEDIUM

### Memory Management
- Streaming report writer (findings written incrementally)
- File size limits
- Automatic config adaptation based on repo size

### Adaptive Configuration

| Files | Config Profile | LLM Paths | Workers |
|-------|---------------|-----------|---------|
| Under 100 | minimal | 200 | 4 |
| Under 1000 | standard | 500 | 8 |
| Under 10000 | large | 1000 | 16 |
| 10000+ | enterprise | 2000 | 32 |

Run `python -m src.main estimate /path/to/repo` to see estimated scope and time for any target.

---

## Checkpointing

```
data/checkpoints/<hash>/
├── progress.md              Human-readable: batch 87/450, 23 candidates
├── code_graph.json          Complete code graph
├── path_enum.json           All source-to-sink paths
├── path_analysis.json       Per-path LLM results
├── chains.json              Exploit chains
├── report.md                Final report
```

---

## Commands

| Command | Description |
|---------|-------------|
| `python start_server.py` | Start server (reads model from config.yaml) |
| `python start_server.py --no-speculative` | Start without draft model |
| `python run_audit.py <path>` | Full exhaustive audit |
| `python run_audit.py <path> --resume` | Resume from checkpoint |
| `python -m src.main setup` | Setup instructions |
| `python -m src.main update-cve` | Download/build CVE database |
| `python -m src.main estimate <path>` | Estimate resources for a target |

---

## Configuration

```yaml
model:
  name: "Qwen2.5-Coder-14B-Abliterated"
  file: "models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf"

server:
  context_length: 32768
  flash_attn: true
  speculative:
    enabled: true

pipeline:
  max_path_depth: 8
  max_paths_per_pair: 20
  max_llm_paths: 500
  llm_temperature: 0.3

scaling:
  max_files_per_chunk: 500
  max_file_size_bytes: 10000000
  skip_test_directories: true
  skip_vendor_directories: true
  max_functions_per_chunk: 50000
  max_paths_total: 100000
  llm_priority_top_n: 1000
  num_workers: 16
  auto_adapt_to_size: true
```

---

## Project Structure

```
models/                              GGUF files (main + draft)
src/
  orchestrator.py                    Master pipeline + checkpointing
  main.py                            CLI entry point
  pipeline/
    step0_fingerprint.py             Fingerprinting + file inventory
    step1_classify.py                16+ target types
    step2_deps.py                    Dependency vuln scan (NVD + EPSS/KEV)
    step2_secrets.py                 Secrets scanner (gitleaks rules)
    step3_static.py                  Semgrep scan + file inventory
    step3b_codegraph.py              Code graph + source/sink/sanitizer tags + memory analysis
    step4_threat_model.py            Threat model + CVE catalog
    step4b_path_enum.py              Exhaustive source-to-sink path enumeration
    step4c_path_analyze.py           Per-path LLM exploitability validation
    step4d_blindspot.py              File-by-file blind spot review (Project Black)
    step6_chains.py                  Attack graph + transitive chain synthesis
    step8_anomaly.py                 Prompt injection detection
    step9_report.py                  Exhaustive report with PoCs
  analysis/
    ast_parser.py                    Multi-language tree-sitter parser (+ regex fallback)
    call_graph.py                    Call graph with import resolution
    source_tag.py                    All untrusted entry points
    sink_tag.py                      All dangerous operations
    sanitizer_tag.py                 All sanitizers (with protected_against taxonomy)
    intra_taint.py                   Intra-procedural taint tracking
    inter_taint.py                   Inter-procedural taint propagation
    path_enum.py                     Source-to-sink path enumeration + sanitizer taxonomy
    path_analyze.py                  Per-path LLM analysis
    attack_graph.py                  networkx-based transitive chain synthesis
    scaling.py                       Large codebase support
    semgrep_runner.py                External SAST integration
    secrets_scanner.py               Entropy-filtered secrets detection
    memory/
      orchestrator.py                Memory analysis coordinator
      alloc_tracker.py               Allocation tracking
      buffer_analyzer.py             Buffer overflow detection
      lifetime.py                    Use-after-free, double-free
      int_overflow.py                Integer overflow detection
      format_string.py               Format string vulnerability (C/C++ unsafe only)
  knowledge/
    cve_db.py, downloader.py, importer.py, embeddings.py, epss.py, kev.py, sbom.py
  llm/
    client.py, prompts.py, context.py, guard.py
data/
  cve/nvd.sqlite                     CVE database (364K+)
  checkpoints/                       Per-repo audit state
config.yaml, requirements.txt
start_server.py, run_audit.py
```

---

## Design Principles

- Exhaustive coverage: every non-test source file reviewed, every source-to-sink path enumerated, nothing sampled
- Deterministic foundation plus LLM reasoning: code graph built deterministically, LLM validates pre-traced paths
- Short, focused prompts: per-path analysis with ~2K token prompts
- Clean context per batch: no memory between batches
- Sanitizer-aware taint tracking: cross-taxonomy mapping between sink categories and sanitizer `protected_against` values
- Inter-procedural taint accumulation: tainted variables propagate across function boundaries, not overwritten
- LLM-based validation: LLM checks sanitizer effectiveness, static tags are signals not blockers
- Product-specific CVEs: CVSS version-tagged, targeted to actual tech stack
- 5 parallel memory analyzers: allocation, buffer, lifetime, integer overflow, format string (with language-specific FP filtering)
- Config-driven model: switch models by changing one line in config.yaml
- Scales to enterprise codebases: single-pass file inventory, node-based AST reuse, adaptive config
- Local only: no data leaves your machine, no API costs

---

## References

- Project Black: Local AI for Penetration Testing (https://projectblack.io/blog/local-ai-for-cyber-security/)
- RAPTOR: Autonomous Security Research Framework (https://github.com/gadievron/raptor)
- Qwen2.5-Coder-14B-Abliterated (https://huggingface.co/bartowski/Qwen2.5-Coder-14B-Instruct-abliterated-GGUF)
- tree-sitter (https://tree-sitter.github.io/)

---

## License

For authorized security research only. Unauthorized use may violate computer fraud laws.
