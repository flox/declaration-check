# declaration-check

Checks that a flox repository declares what it is and who owns it.

Every repository carries a `catalog-info.yaml` — a [Backstage entity
descriptor](https://backstage.io/docs/features/software-catalog/descriptor-format)
— saying how exposed it is, how much human review a dependency bump needs, its
maturity, and which area of responsibility owns it. This repository holds the
check that the declaration is present and complete, and nothing else.

```yaml
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: declaration-check
  labels:
    flox.dev/classification: internal-tooling   # customer-facing | distribution | internal-tooling | non-shipping | non-production
    flox.dev/max-tier: manual                   # auto | assisted | manual
spec:
  type: service
  lifecycle: active                             # experimental | active | deprecated
  owner: group:linear/aor-59
```

A repository holding several independently-owned parts declares a `kind: Location`
at its root listing each part's descriptor, which is Backstage's own monorepo
model. The check follows those targets, and fails if a directory carrying a
dependency manifest is not covered by any of them — adding a component without
declaring it is the ordinary mistake, and the root still validates, so nothing
else notices.

## Running it

An organisation ruleset names `.github/workflows/declaration-check.yml` as a required
workflow, so repositories do not call it themselves. To run it against a checkout:

```
python3 declaration.py --path catalog-info.yaml
```

It exits 0 when the declaration is complete, 1 with the fields that are missing or
misspelt and a filled-in example to paste, and 2 when it could not tell.

## Why this repository is separate, and public

A ruleset may only require a workflow from a repository at least as visible as the
one it runs on: a public source runs anywhere, an internal source on internal and
private repositories, a private source only on private ones. The check has to run
everywhere, and most flox repositories are public, so the check is public.

It is also the half that holds no credential, which is the invariant worth keeping
separate. The check only ever reads a file out of the repository it is checking.
What happens with the result — reconciling against the compliance platform, the
tier matrix, the record that the check held — lives in a private repository with
the one key it needs.

## Tests

```
flox activate -- python3 -m unittest discover -p 'test_*.py'
```

They cover rejection rather than acceptance: a check that accepts a malformed
declaration reports success, and that is the failure nobody sees.
