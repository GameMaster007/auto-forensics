# Synthetic case

These files are fiction for the offline demo. They are not from a real
incident. The address `203.0.113.19` is from the documentation range in
RFC 5737. The account name and the host name are placeholders.

| File | What the demo uses it for |
| --- | --- |
| `events.json` | Two made-up events. The first is a Sysmon-style process start and is cited as row 1. |
| `persistence.csv` | Two made-up persistence rows. |
| `notes.txt` | One analyst note in `timestamp\|type\|text` form. |
| `sample_loader.bin` | A short text file with a `MZ` prefix and a few suspicious strings. It is not a Windows executable. The binary citation is offset 0. |

Run it with `--llm mock`, as described in the repository README.
