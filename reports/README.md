# reports/

Default destination for generated HeaderSpecter reports.

The committed `sample-*` files were produced against the bundled demo lab
(`python3 examples/demo_server.py`) so you can see every output format without
running a scan first:

| File | Produced by |
|---|---|
| `sample-report.html` | `headerspecter http://127.0.0.1:8080/weak --html reports/sample-report.html` |
| `sample-report.md` | `headerspecter http://127.0.0.1:8080/weak --md reports/sample-report.md` |
| `sample-batch.json` | `headerspecter -l examples/targets.txt -o reports/sample-batch.json` |
| `sample-findings.csv` | `headerspecter -l examples/targets.txt --csv reports/sample-findings.csv` |

Open `sample-report.html` in a browser — it is a single self-contained file with
no external CSS, fonts or JavaScript.

Everything else written here is ignored by git (see `.gitignore`), so this is a
safe place to keep engagement output.
