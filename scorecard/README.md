# scorecard/

`silentwitness report` builds `site/index.html` from the latest run of each
adapter in `evidence/`: one row of cells per signer, the notable results, and
every case with the PSBT sent and returned.

CI (`.github/workflows/scorecard.yml`) runs the suites on every push to `main`
and publishes the page to GitHub Pages.

`annotations.json` holds short plain-language explanations of results, keyed by
adapter and case id. Write one for every failure and skip, and only state what
the evidence shows.

Findings in released firmware never go here until the disclosure policy allows
(see `docs/disclosure-policy.md`).
