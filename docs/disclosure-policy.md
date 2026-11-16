# Disclosure policy

SilentWitness exists to make signers safer, not to embarrass their maintainers.
Maintainers hear about a problem before anyone else does, and findings are
turned into tests in their own repositories wherever possible.

## Who hears first, and when it becomes public

| Finding | Report to | Public when |
|---|---|---|
| Failure on an unreleased branch or open PR | PR comment or issue, after asking the author how they want it | Immediately |
| Released firmware can lose or lock funds | The project's security contact, privately | After a fix ships, or 90 days after the report, whichever comes first |
| Display or usability problem | Normal issue | Immediately |

"Released" means a tagged release or a build users are told to install.

## What a report contains

- the minimal PSBT that shows the problem (base64)
- the expected result, with the BIP rule it comes from
- the actual result: returned PSBT, error, screenshot or video
- the signer's firmware or library commit and the vector commit

Reports are short. Small DIY projects have little review time.

## While a finding is private

- The case is kept out of the public repository and out of CI logs.
- The public scorecard shows the affected signer and firmware as
  "private finding pending" with no details.
- If the maintainer asks for more time and is actively working on a fix, the
  90 days can be extended by agreement.

## After disclosure

The case, its evidence and the fix commit are published in the scorecard, and
the case is offered upstream as a test or BIP vector. Maintainers are credited
for the fix if they want to be.

## Safety

All cases use public test keys on signet or regtest. SilentWitness never needs
real seeds or funds, and reports never include them.
