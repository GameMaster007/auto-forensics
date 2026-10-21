# Contributing

Thanks for looking at auto-forensics. The useful change is one that a
reviewer can check against an artifact: a citation, a test, or a
documented limit.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows PowerShell, create the virtual environment with
`python -m venv .venv`, activate it with `.venv\Scripts\Activate.ps1`,
and install with `python -m pip install -e ".[dev]"`.

## Checks

```bash
ruff check src tests
python -m pytest -q
```

The offline demo needs no API key:

```bash
auto-forensics run \
  --case-id demo-synthetic \
  --input-dir examples/case1/artifacts \
  --output-dir output/demo-synthetic \
  --llm mock
```

## Rules for a change

- Do not commit secrets, tokens, `.env` files, or real evidence.
- Do not add real packet captures or disk images. Generate fixtures in
  the test, or extend the synthetic files under `examples/case1`.
- A new finding path has to cite an ingested artifact, or the report
  will drop it. Add a test that shows the drop.
- Evidence that would be sent to a model has to sit inside the quote
  fence built by `quote_untrusted`. Do not place evidence text in the
  instruction string.
- A new worker action has to be allow-listed on `ToolRegistry` and
  covered by the manifest's `tool_calls` list. Do not call a shell or
  a network client from a worker by a name that is not on that list.
- `PluginRegistry` loads parsers and detectors. It is not the tool
  allow-list. Keep them separate.
- Do not publish a release, a tag, or a package to PyPI from a pull
  request.

## Pull requests

Use the pull request template. Say what you ran. If you change the
citation rule, the manifest, or the worker boundary, update
`docs/ROADMAP.md` so the status table stays true.

## Conduct

See `CODE_OF_CONDUCT.md`. Security reports go through `SECURITY.md`,
not a public issue.
