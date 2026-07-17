# Third-Party Licenses

VibeScan's own source code and rule files are licensed under the MIT License
(see `LICENSE`). This project also bundles third-party rule content under
different terms, listed below. The MIT License covers only VibeScan's own files;
it does not relicense the bundled content.

## opengrep-rules

- **Location:** vendored at `assets/opengrep-rules/` (git submodule) or fetched at
  runtime into `~/.vibescan/opengrep-rules/`
- **Upstream:** https://github.com/opengrep/opengrep-rules
  (a fork of https://github.com/semgrep/semgrep-rules)
- **License:** GNU Lesser General Public License v2.1 (LGPL-2.1), with the
  **Commons Clause License Condition v1.0** applied on top.
- **Licensor:** Semgrep, Inc. (https://semgrep.dev)

### What the Commons Clause means here

The Commons Clause removes the right to **Sell** the covered rule content, where
"Sell" means providing to third parties, for a fee or other consideration
(including hosting or support/consulting fees), a product or service whose value
derives entirely or substantially from the functionality of the software.

Consequences for anyone using or redistributing this repository:

- Personal use, internal use, and **free** (non-paid) distribution are permitted.
- Offering VibeScan as a **paid product, paid SaaS, or paid support** while these
  rules are bundled is **not** permitted, because the scan value derives
  substantially from them.
- Any modifications you make to files under `assets/opengrep-rules/` remain under
  LGPL-2.1 + Commons Clause, not MIT.
- This notice (including the Commons Clause condition) must travel with any
  redistribution.

> This is a plain-language summary, not legal advice.
