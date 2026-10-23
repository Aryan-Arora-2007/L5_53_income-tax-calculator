# Issues found in `tax_calculator.py`

Line numbers refer to the **original** file (commit `638c236`).
Reports are in `reports/` (`*_before.txt` and `*_after.txt`).

| Tool | Before | After |
|------|--------|-------|
| Pylint | 4.57 / 10 (50 messages) | 10.00 / 10 |
| Bandit | 6 issues (2 High, 3 Medium, 1 Low) | 0 issues (2 reviewed `# nosec B412`) |
| Flake8 | 23 messages | 0 |

## Security (Bandit) - fixed in commit 1

| Issue | Type | Line(s) | Description | Fix Approach |
|-------|------|---------|-------------|--------------|
| CGIHandler / httpoxy (B412, **High**) | Security | 6, 92 | A CGI server copies the request's `Proxy` header into `HTTP_PROXY`, so an attacker can redirect the app's outgoing requests. | Remove `HTTP_PROXY` from the environment before `CGIHandler().run()`; keep the import/call with a justified `# nosec B412`. |
| ECB cipher mode (B305, **Medium**) | Security | 77 | AES-ECB is deterministic: identical PANs give identical ciphertext and patterns leak. The demo even printed `True` for "same PAN encrypts the same way twice". | Use AES-GCM with a random 12-byte nonce (authenticated encryption); output is nonce + ciphertext as hex. |
| Hard-coded encryption key | Security | 15 | `PAN_KEY` was a literal in source code, so anyone with the repo has the key. Bandit does not flag byte-string keys, found by review. | Removed the constant. `load_pan_key()` reads `PAN_ENCRYPTION_KEY` (hex) or generates a random per-process key. |
| 1024-bit RSA key (B505, **Medium**) | Security | 83 | RSA keys below 2048 bits are considered breakable. | `key_size=2048`. |
| minidom XML parsing (B318 Medium, B408 Low) | Security | 5, 86 | The standard-library XML parser is vulnerable to entity-expansion / XXE-style attacks on untrusted Form 16 files. | Parse with `defusedxml.ElementTree`. A scratch test confirms an entity-bomb document is now rejected. |

## Style (Flake8) - fixed in commit 2

| Issue | Type | Line(s) | Description | Fix Approach |
|-------|------|---------|-------------|--------------|
| Unused imports (F401) | Style | 2-4 | `os`, `sys`, `json` imported, never used. | Removed `sys` and `json`; `os` is now used by the key/nonce/CGI code. |
| Missing blank lines (E302, E305) | Style | 18, 34, 43, 50, 63, 70, 76, 82, 85, 91, 94, 106 | PEP 8 requires two blank lines around top-level definitions. | Added them. |
| Lines too long (E501) | Style | 16, 98, 102, 103 | Lines over 79 characters. | Wrapped lines and split long expressions into named locals. |
| Semicolon statement (E702) + unused locals (F841) | Style / Bug | 36 | `bracket = slabRate(taxable); checked = False` - two statements on one line, both variables never used. | Deleted both. |
| Bare `except` (E722 / W0702) | Style / Bug | 73 | Catches everything, including `KeyboardInterrupt`, and hides real errors. | Catch only `TypeError`; later replaced by an explicit `isinstance` check. |

## Quality (Pylint) - fixed in commit 3

| Issue | Type | Line(s) | Description | Fix Approach |
|-------|------|---------|-------------|--------------|
| Names not snake_case (C0103) | Quality | 18-104 | `slabRate`, `newRegimeTax`, `taxAmount`, ... | Renamed all functions and variables. |
| Missing docstrings (C0114, C0116) | Quality | 1, 18-94 | No module or function documentation. | Added docstrings. |
| Too many returns + elif after return (R0911, R1705) | Quality | 18-32 | Seven-branch `if/elif` chain in `slabRate`. | Replaced by a `NEW_SLABS` table, matching how `OLD_SLABS` is already written. |
| Unused arguments (W0613) | Quality | 85, 91 | `strict` and `debug` do nothing. | Removed them. |
| Chained comparison (R1716) | Quality | 44 | `age >= 60 and age < 80`. | `60 <= age < 80`. |
| `%` formatting (C0209) | Quality | 99, 100, 104 | Old-style string formatting. | f-strings. |
| `main()` runs on import | Quality | 106 | Importing the module executes the demo. | `if __name__ == "__main__":` guard. |

## Logic bugs found by reading the output - fixed in commit 4

None of these is reported by any of the three tools.

| Issue | Type | Line(s) | Description | Fix Approach |
|-------|------|---------|-------------|--------------|
| Flat rate instead of progressive slabs | Bug | 18-32, 37 | `slabRate` returned one rate and multiplied it by the *whole* income, so salary 18,00,000 gave tax 3,58,800 - higher than the old regime. | New `slab_tax()` charges each rate only on the income inside its slab (shared by both regimes). Result: 1,50,800. |
| Rebate boundary (`<` vs `<=`) | Bug | 39 | Taxable income of exactly 12,00,000 got no 87A rebate, so salary 12,75,000 paid 1,24,800. | `taxable <= REBATE_LIMIT_NEW`. Result: 0. |
| Cess charged on a rebated tax | Bug | 38-41 | Cess was computed *before* the rebate zeroed the tax, then still added. | Apply the rebate first, then cess on the remaining tax. |
| Inverted regime comparison | Bug | 66-68 | `if newTax > oldTax: return "new"` recommended the *more expensive* regime. | Return `"old"` only when old tax is lower; ties go to `"new"`. |
| Age-80 boundary | Bug | 46 | `age > 80` gave an 80-year-old the ordinary 2,50,000 exemption. | `age >= 80`. |
| Unanchored PAN regex | Bug | 72 | `re.match` ignores trailing text, so `ABCDE1234FXYZ` was "valid". | `re.fullmatch` plus an `isinstance(pan, str)` check. |
| Debug `print` inside a calculation | Quality | 60 | `old_regime_tax` printed "Last slab rate applied" every call, using the loop variable after the loop. | Removed. |
| Truncating `int()` on float tax | Bug | 41, 61 | `int()` can drop a rupee when a float lands just below a whole number. | `round()`. |
| Missing / malformed Form 16 fields | Robustness | 87-89 | A missing `<salary>` raised an unclear `AttributeError`/`IndexError`. | Raise `ValueError("Form 16 XML must contain <salary> and <tds>")`. |

## Known simplifications left unchanged

The slabs are "for teaching only", so these were not added: no old-regime 87A rebate, no marginal relief for new-regime taxable income just above 12,00,000, no cap on 80C (the demo passes 2,00,000) or 80D, and no rounding of tax to the nearest ten rupees.
