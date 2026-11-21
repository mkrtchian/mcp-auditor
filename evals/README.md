# evals

The instruments that measure the auditor, and what they run on.

- `run_honeypot_suite.py`, `run_judge_eval.py`, `run_detection.py`, `run_detection_holdout.py` and `run_nuisance.py` run the honeypot suite, the judge eval, the two layers of the detection suite and the nuisance suite. `run_census.py` builds the census and `run_probe.py` runs the model probe.
- `baselines/` holds the recorded baselines the gates compare to, and `fixtures/` the judge cases, the probe corpus and the baseline of the fault injection test.
- `census.json`, `nuisance_walk_record.json` and `nuisance_admission.json` record the flaws, the nuisance walk and the admitted servers.
- `cve/` holds the code of the CVE benchmark and the reports of the detection holdout runs and of the nuisance holdout run (`cve/holdout_runs/`), `docker/` the Dockerfiles of the servers the benchmark audits, and `stand_ins/` what the stand-ins serve.

The results and how to read them are in [`docs/evals.md`](../docs/evals.md), the commands in [`CONTRIBUTING.md`](../CONTRIBUTING.md), and the method notes beside the code: [`census_method.md`](census_method.md), [`judge_fixture_method.md`](judge_fixture_method.md), [`fault_injection_method.md`](fault_injection_method.md) and [`probe_method.md`](probe_method.md).
