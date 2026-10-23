# Reflection

The handout PDF does not print the reflection questions, so these are the four
standard questions for this lab. Replace the headings if your instructor's
list differs.

## 1. Which issues were the easiest and which were the hardest to fix?

Easiest were the mechanical ones: unused imports, blank lines, line length and
snake_case names. Flake8 and Pylint point at the exact line and the fix is
obvious. Hardest were the security findings, because they needed a design
decision rather than an edit. Removing AES-ECB meant choosing AES-GCM, a nonce
scheme, and a place for the key that is not the source code. The CGIHandler
finding (B412) has no one-line fix: I mitigated httpoxy by removing
`HTTP_PROXY` and documented a `# nosec` instead of deleting the feature. The
hardest bugs overall were the ones no tool reported (see question 2).

## 2. Did the tools miss anything, or report anything that was not a real problem?

They missed the bugs that matter most for a tax calculator: a flat rate applied
to the whole income instead of progressive slabs, a rebate boundary using `<`
instead of `<=`, an inverted "better regime" comparison, and an age-80
boundary error. I only found those by running the program and checking whether
the numbers made sense. Static analysis cannot know that 18,00,000 should not
cost more under the regime it recommends. Bandit also did not flag the
hard-coded key because it was a byte string. On the other side, B412 is a
real risk only when the code runs under CGI, so after mitigating it I
suppressed it with a justification rather than treating it as a defect. Many
Pylint messages (docstrings, naming) are style, not defects.

## 3. How would you fit these tools into a normal workflow?

Run Flake8 and Pylint in the editor and in a pre-commit hook so style issues
never reach review, and run Bandit plus Pylint in CI with a minimum score so a
pull request fails when security or quality regresses. Keep a short list of
reviewed suppressions (like the two `# nosec B412` lines) so exceptions are
visible in review. Pair the tools with unit tests: the scratch checks I wrote
for the tax figures are what caught the logic bugs, and would belong in the
repository as a test suite.

## 4. What changed in the code's quality, readability, security and reliability?

Pylint went from 4.57 to 10.00, Bandit from 6 findings (2 High) to 0, and
Flake8 from 23 messages to 0. The code is now documented, consistently named
and importable without side effects. Security improved concretely: random
nonces and authenticated encryption, no key in the source, a 2048-bit RSA key,
and an XML parser that rejects entity attacks. Reliability improved most from
the manual fixes: the printed tax figures are now correct (12,75,000 pays 0,
18,00,000 pays 1,50,800 under the new regime), the recommendation is no longer
backwards, and invalid PAN or Form 16 input is rejected clearly.
