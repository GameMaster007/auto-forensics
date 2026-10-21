# Security

auto-forensics reads evidence that you should treat as hostile. A log
line, a binary string, or a file name can be an attack on the analyst
workstation or on the model, not only a record of an attack on the
original host.

## Threat model

| Threat | What this version does |
| --- | --- |
| A path outside the evidence directory is ingested, or a symlink escapes the case. | Case IDs are restricted to a short character set. Ingest checks an allow-list of roots (`AUTO_FORENSICS_ALLOWED_INGEST_ROOTS`, defaulting to the home directory). Symlinks are skipped. Text reads are size-capped. |
| A huge or very numerous tree exhausts disk or memory. | Ingest stops at a file-count and file-size cap. The manifest hashes at most 10,000 files and stops walking deeper than 20 path parts. |
| Evidence text tells the model to ignore its instructions. | Model prompts put evidence in one JSON block between `<<<EVIDENCE_DATA` and `EVIDENCE_DATA>>>`. The markers are stripped from the payload so the block cannot be closed early. A short list of injection phrases is redacted before the block is built. The offline mock does not copy evidence text into the finding. |
| The model invents a citation, or a sentence that names a real row but is not in it. | A finding is kept only when `artifact_id` and `sha256` match an artifact this run hashed. The verifier then re-opens that file, checks the hash, and drops the finding unless each claim sentence appears in the cited row. A judge can reject a claim the rules accepted. It cannot restore one the rules rejected. Verdict reasons do not copy the cited text. |
| The model names itself as a different worker. | `MemoryCaseStore.add_findings` sets `Finding.worker` from the worker argument. |
| A worker calls a tool that was not allow-listed. | `ToolRegistry.call` refuses the name, logs `denied`, and raises. The pipeline only allow-lists its own stages. This is not a sandbox. Code that imports a function directly still runs. |
| Optional parsers start another program (`python-evtx` is in-process; Volatility, and some prefetch or MFT helpers, may be subprocesses). | Those programs receive paths from the evidence tree. They are outside this process's allow-list. Do not point them at evidence you do not trust on a machine that holds other cases. |
| An API key or a case file is committed. | CI runs gitleaks. Do not commit `.env` files, tokens, or real evidence. Keys are read from the environment at runtime. |
| A hosted model receives real case data. | The demo does not. `--llm mock` makes no network call. `--llm ollama` talks to the endpoint you configure. Do not send case data to a service unless you are allowed to. |

## What is not defended yet

- The verifier checks that claim sentences occur in the cited row. It
  does not decide whether the sentence is a fair conclusion from that
  row. A true sentence that does not quote the row is dropped. A false
  sentence that happens to repeat the row is kept.
- `review_status` cannot be set to accepted or rejected by an analyst.
  `verification: supported` is the verifier, not an analyst decision.
- The tool log is not a full audit of every function call in the
  process. It records the allow-listed stages the pipeline worker
  invoked.
- The in-run `CaseStore` and the SQLite case database are separate.
  Tampering with one is not detected by the other.
- There is no claim of resistance to a malicious local model, a
  compromised dependency, or a person who can already write files in
  the case directory.

## Reporting

Please report a vulnerability through a private GitHub security
advisory on [GameMaster007/auto-forensics](https://github.com/GameMaster007/auto-forensics/security).
Do not open a public issue, and do not include real evidence in the
report. Describe the version, the input shape, and the effect.

If you believe you have found a problem in the citation check or the
prompt fence, a synthetic fixture is enough.
