"""The per-repository declaration: what a repository says about itself.

ADR-001 fixes the facts a repository declares and deliberately leaves the file
format open. This module is where that choice is made concrete, and it is the only
place that knows the format: everything downstream takes the dict this returns, so
changing the encoding later means changing this file and nothing else.

Today the encoding is a Backstage entity descriptor at `flox-info.yaml` — their
schema, our filename, because `catalog-info.yaml` would put the Flox Catalog's
word in every repository. That
is an implementation detail, not a commitment — see ADR-001 and ADR-008's
withdrawal. Backstage's own schema validates the envelope; it does not validate
our facts, because `metadata.labels` is an open string map and will accept a
misspelt key or a missing one without complaint. So the content check below is
ours and cannot be delegated.

Nothing here reads a credential. That is what lets `scope-declared` run in every
repository in the organisation: the check only ever reads a file out of the
repository it is checking.
"""

import argparse
import datetime
import os
import re
import sys

PREFIX = "flox.dev/"

# One field answers "what does this repository reach", and the answer decides both
# whether it is in the audit boundary and which row of the matrix applies. Two
# fields — a scope flag and an exposure class — meant a reader had to hold the
# difference between "in scope" and "ships something", which read as a
# contradiction in the three repositories where they crossed. ADR-011.
CLASSIFICATION = PREFIX + "classification"
MAX_TIER = PREFIX + "max-tier"

# Annotations, not labels: nobody selects a repository by the date it is expected
# to ship, or by which of its workflows publish. Both are read once the
# repository is already in hand.
PROD_DATE = PREFIX + "expected-production"
RELEASE_WORKFLOWS = PREFIX + "release-workflows"

# Outside the audited boundary. Sprinto calls this Not Production and so do we,
# because that field's audience is the people reading Sprinto. The word
# "production" appears nowhere else in the file: `spec.lifecycle` carries
# maturity, and its taxonomy is experimental / active / deprecated.
NON_PRODUCTION = "non-production"

# In the boundary, most to least exposed. These are the values a repository may
# declare, which is why they live here rather than with the matrix they index:
# the declaration format is the contract, and the matrix is built on top of it.
# `register.py` reads both names back off this module so there is one definition
# of each, the mistake that two spellings of "production" taught us once already.
EXPOSURES = ["customer-facing", "distribution", "internal-tooling", "non-shipping"]

# In the boundary, most to least exposed, and these are the matrix rows.
CLASSIFICATIONS = EXPOSURES + [NON_PRODUCTION]

# Least to most human involvement. Ordered, so a ceiling is a max() over indices.
TIERS = ["auto", "assisted", "manual"]

LIFECYCLES = ["experimental", "active", "deprecated"]

# A repository holding several independently-owned parts declares a Location at
# its root, listing the descriptors for each. That is Backstage's own monorepo
# model rather than something invented here: a Location is "a marker that
# references other places to look for catalog data", and its targets may be
# relative paths resolved against the Location itself.
#
# It matters beyond tidiness. floxhub's subtrees have different owners, and
# today they would be forced to share one classification and one automation
# ceiling. Declaring each part separately lets `src/web-ui` be customer-facing
# while `src/integration-tests` ships nothing, which is simply true.
LOCATION_KIND = "Location"
COMPONENT_KIND = "Component"

# A vulnerability is reported against a dependency manifest, so a directory
# holding one is a directory that can produce findings. Every one of them has to
# be covered by a declaration, or a part of the repository is quietly outside the
# process while the repository as a whole looks declared.
#
# This is the rule that makes a monorepo safe to add to. Someone creating
# src/newthing with a lockfile and no descriptor is the ordinary case, not a
# malicious one, and nothing else would catch it: the Location still validates,
# because its listed targets are all still there.
MANIFESTS = (
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "pyproject.toml",
    "Cargo.lock", "Cargo.toml", "go.mod", "Gemfile.lock", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "mix.lock", "pubspec.lock",
    # GitHub Actions is an ecosystem like any other and its dependencies are
    # pinned third-party code. An action's own `uses:` references live in
    # action.yml, which is what Dependabot updates for a composite or JavaScript
    # action, so a directory holding one carries dependencies.
    "action.yml", "action.yaml",
)

# Workflows are the other half of that ecosystem, and they are not a fixed
# filename — every file in this directory is a manifest. Treated specially
# rather than by extension, because a .yml anywhere else is configuration.
WORKFLOW_DIRECTORY = ".github/workflows"

# Not swept for manifests: vendored or generated trees are somebody else's
# dependencies, and the tooling does not raise findings against them either.
SKIP_DIRECTORIES = {
    ".git", ".flox", "node_modules", "vendor", "target", "dist", "build",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
}

# An out-of-scope repository that genuinely never becomes production says so
# rather than naming a date, so "we have not thought about it" and "we thought
# about it and the answer is no" are different answers.
NEVER = "never"

# The namespace in a Backstage entity reference is the one part we are free to
# choose, and it is doing work here rather than carrying the conventional
# `default`. An AoR lives in Linear and resolves there; the sentinel below
# resolves nowhere by design. Encoding that in the namespace means the checker
# tells them apart structurally, instead of matching a reserved name that
# somebody could one day create in Linear by accident.
AOR_NAMESPACE = "linear"
LOCAL_NAMESPACE = "flox"

# A repository with no Area of Responsibility yet declares this rather than
# leaving the field out. The check passes, and the collector can list every
# repository carrying it — so unowned repositories surface instead of being
# indistinguishable from unanswered ones. Only valid out of scope.
UNOWNED = "group:%s/unowned" % LOCAL_NAMESPACE

AOR_PATTERN = re.compile(
    r"^(group:%s/aor-\d+|%s)$" % (re.escape(AOR_NAMESPACE), re.escape(UNOWNED)))


class Invalid(Exception):
    """The declaration is absent, unparseable, or incomplete.

    Carries every problem found rather than the first, because the person
    reading the failed check should fix the file once.
    """

    def __init__(self, problems):
        self.problems = problems
        super().__init__("; ".join(problems))


def _labels(doc):
    meta = doc.get("metadata")
    return meta.get("labels") or {} if isinstance(meta, dict) else {}


def _annotations(doc):
    meta = doc.get("metadata")
    return meta.get("annotations") or {} if isinstance(meta, dict) else {}


def targets(text):
    """The descriptors a Location points at, or None if this is not a Location.

    Raises Invalid if it is a Location but an unusable one, because a root that
    lists nothing leaves every part of the repository undeclared while looking
    like an answer.
    """
    doc = _document(text)
    if doc.get("kind") != LOCATION_KIND:
        return None

    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    listed = spec.get("targets")
    if listed is None and spec.get("target"):
        listed = [spec["target"]]
    if not isinstance(listed, list) or not listed:
        raise Invalid(["a Location must list spec.targets: the descriptors for "
                       "each separately-owned part of this repository"])

    cleaned = []
    for target in listed:
        if not isinstance(target, str) or not target.strip():
            raise Invalid(["spec.targets contains something that is not a path"])
        if "://" in target:
            raise Invalid([
                "spec.targets must be paths inside this repository, not URLs: "
                "%r. A declaration is evidence about the repository it sits in, "
                "and a target elsewhere could change without a reviewed commit "
                "here." % target])
        # Strip one leading "./" rather than lstrip("./"), which takes a *set*
        # of characters and ate the dot of a dotted directory: "./.github/x"
        # came back as "github/x", and the check then reported a target that
        # does not exist while the real one went unchecked. Relative-path
        # prefixes are removed one segment at a time for the same reason.
        cleaned_target = target.strip()
        while cleaned_target.startswith("./"):
            cleaned_target = cleaned_target[2:]
        cleaned.append(cleaned_target)
    return cleaned


def _document(text):
    try:
        import yaml
    except ImportError:  # pragma: no cover - the workflow installs it
        raise Invalid(["PyYAML is not available to the checker"])
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise Invalid(["the file is not valid YAML: %s" % exc])
    if not isinstance(doc, dict):
        raise Invalid(["the file does not contain a YAML mapping"])
    return doc


def parse(text):
    """Read a declaration. Raises Invalid with every problem found.

    Returns the facts as a dict, in the vocabulary `register.py` already uses, so
    the collector and the approver never see the file format.
    """
    doc = _document(text)
    if doc.get("kind") == LOCATION_KIND:
        raise Invalid(["this is a Location, which points at other descriptors "
                       "rather than declaring anything itself"])

    problems = []
    labels = _labels(doc)

    classification = labels.get(CLASSIFICATION)
    if classification not in CLASSIFICATIONS:
        problems.append("%s must be one of: %s"
                        % (CLASSIFICATION, ", ".join(CLASSIFICATIONS)))
        in_scope = None
    else:
        in_scope = classification != NON_PRODUCTION

    lifecycle = (doc.get("spec") or {}).get("lifecycle") if isinstance(doc.get("spec"), dict) else None
    if lifecycle not in LIFECYCLES:
        problems.append("spec.lifecycle must be one of: %s" % ", ".join(LIFECYCLES))

    max_tier = labels.get(MAX_TIER)
    if max_tier not in TIERS:
        problems.append("%s must be one of: %s"
                        % (MAX_TIER, ", ".join(TIERS)))

    owner = (doc.get("spec") or {}).get("owner") if isinstance(doc.get("spec"), dict) else None
    if not isinstance(owner, str) or not AOR_PATTERN.match(owner):
        problems.append(
            "spec.owner must be an Area of Responsibility reference such as "
            "group:%s/aor-59, or %s for a repository that has none yet"
            % (AOR_NAMESPACE, UNOWNED))
    elif owner == UNOWNED and in_scope:
        # The sentinel is how an out-of-scope repository defers the question.
        # In scope it would let a repository that matters claim no owner, which
        # is the bystander problem this process exists to remove.
        problems.append(
            "%s is not permitted in scope: a repository in audit scope names a "
            "real Area of Responsibility" % UNOWNED)

    prod_date = _annotations(doc).get(PROD_DATE)
    if in_scope is False:
        date_problems, prod_date = _check_production_date(prod_date)
        problems.extend(date_problems)
    elif prod_date is not None and in_scope:
        problems.append("%s applies only out of scope" % PROD_DATE)

    if problems:
        raise Invalid(problems)

    return {
        "name": (doc.get("metadata") or {}).get("name"),
        "in_scope": in_scope,
        "classification": classification,
        # The matrix speaks of exposure, and an out-of-scope repository has no
        # row in it, so this is None rather than a fifth row nobody drew.
        "exposure": classification if in_scope else None,
        "max_tier": max_tier,
        "lifecycle": lifecycle,
        "aor": owner,
        "expected_production": prod_date,
        "release_workflows": sorted(_release_workflows(doc)),
    }


def _check_production_date(value):
    """Out of scope, a repository says when it expects to be in scope.

    Robin's case, from the 2026-10-12 compliance review: a repository set up
    while it is still being built is declared non-production truthfully, and then
    becomes production with nothing revisiting the answer.

    Returns (problems, normalised value). An unquoted ISO date is parsed by YAML
    into a date object before this ever sees it, so it is normalised back to a
    string rather than rejected. That is deliberately more forgiving than the
    scope label, which refuses an unquoted `true`: a date means the same thing
    either way, whereas the scope label is the one field whose misreading changes
    what is in audit scope, and a bare `true` there is the trap ADR-001 names.
    """
    if value is None:
        return (["%s is required out of scope: an ISO date, or \"%s\"" % (PROD_DATE, NEVER)],
                None)
    if isinstance(value, datetime.date):
        return ([], value.isoformat())
    if value == NEVER:
        return ([], NEVER)
    try:
        datetime.date.fromisoformat(str(value))
    except ValueError:
        return (["%s must be an ISO date (YYYY-MM-DD) or \"%s\", not %r"
                 % (PROD_DATE, NEVER, value)], value)
    return ([], str(value))


def _release_workflows(doc):
    """Workflows that publish a released artifact, per ADR-006.

    Declared rather than detected, because neither triggers nor credential usage
    separate publishers from test runs — `deploy-install-sh.yml` publishes on a
    push to main while holding no secret, and the one workflow that does hold a
    secret only posts to Slack.
    """
    raw = _annotations(doc).get(RELEASE_WORKFLOWS, "")
    return {part.strip() for part in str(raw).split(",") if part.strip()}


def manifest_directories(root="."):
    """Directories under `root` holding a dependency manifest, relative to it.

    "Manifest" means whatever the scanner would raise a finding against, so the
    GitHub Actions ecosystem counts: an alert naming `.github/workflows/ci.yml`
    has to resolve to an owner the same as one naming a lockfile, and until this
    included them a repository could be fully declared and still have an
    alertable surface no declaration covered.
    """
    found = set()
    for here, directories, files in os.walk(root):
        directories[:] = [d for d in directories if d not in SKIP_DIRECTORIES]
        relative = os.path.relpath(here, root)
        relative = "" if relative == "." else relative.replace(os.sep, "/")
        if any(f in MANIFESTS for f in files):
            found.add(relative)
        elif relative == WORKFLOW_DIRECTORY and files:
            found.add(relative)
    return found


def uncovered(declared_paths, root="."):
    """Manifest directories that no declaration covers.

    Coverage is by path prefix, the way CODEOWNERS works: a descriptor at
    `src/openfga` covers `src/openfga/reconcile`. A repository declaring at its
    root therefore covers everything, which is why this rule costs a
    single-component repository nothing.
    """
    covered = sorted(declared_paths)
    gaps = []
    for directory in sorted(manifest_directories(root)):
        if not any(directory == c or (c == "" or directory.startswith(c + "/"))
                   for c in covered):
            gaps.append(directory)
    return gaps


def is_expected_in_production(decl, today=None):
    """True when an out-of-scope repository's expected production date has passed.

    The periodic review chases these rather than re-examining every
    non-production repository by hand.
    """
    value = decl.get("expected_production")
    if not value or value == NEVER or decl.get("in_scope"):
        return False
    today = today or datetime.date.today()
    return datetime.date.fromisoformat(str(value)) <= today


# ---------------------------------------------------------------------------
# The check itself: `scope-declared`, run by every repository in the estate.
#
# Reads the repository's own declaration and nothing else — no credential, no
# network. That is what makes it safe to run everywhere, and why anything
# needing a secret lives in the sync instead.
#
# The failure message is the most important text in this repository. Whoever
# meets it has usually just created a repository, does not know this process
# exists, and wants to merge something unrelated. So it says what is wrong, gives
# a complete starting file with the conservative answers filled in, and only then
# explains why it is being asked.
# ---------------------------------------------------------------------------

DEFAULT_PATH = "flox-info.yaml"

TEMPLATE = """apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: %(repo)s
  labels:
    flox.dev/classification: non-production   # %(classifications)s
    flox.dev/max-tier: auto                   # %(tiers)s
  annotations:
    flox.dev/expected-production: never       # non-production only: an ISO date, or never
spec:
  type: service
  lifecycle: experimental                     # %(lifecycles)s
  owner: %(unowned)s           # the Linear AoR, e.g. group:linear/aor-59
"""

WHY = """\
Why this is required: this repository's audit scope, exposure and owner decide
whether its dependency vulnerabilities are scanned, how closely its updates are
reviewed, and who is told when one needs a person. Declaring it here means the
answer lives in this repository's own history — who changed it, when, and why —
rather than in a console with no record. The people who know the answer are the
ones who own the code, which is why you are being asked rather than someone
guessing later."""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--path", default=DEFAULT_PATH,
                        help="declaration to check (default: %(default)s)")
    parser.add_argument("--repo",
                        default=(os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1]
                                 or os.path.basename(os.getcwd())),
                        help="repository name, used in the example output")
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"),
                        help="file to append a markdown summary to")
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        _report_fail(args, ["%s does not exist" % args.path])
        return 1

    with open(args.path) as fh:
        text = fh.read()
    root = os.path.dirname(args.path) or "."

    try:
        listed = targets(text)
    except Invalid as invalid:
        _report_fail(args, invalid.problems)
        return 1

    if listed is None:
        try:
            decl = parse(text)
        except Invalid as invalid:
            _report_fail(args, invalid.problems)
            return 1
        declared_paths, parts = [""], [(args.path, decl)]
    else:
        problems, declared_paths, parts = [], [], []
        for target in listed:
            full = os.path.join(root, target)
            if not os.path.exists(full):
                problems.append("the root points at %s, which does not exist" % target)
                continue
            with open(full) as fh:
                try:
                    parts.append((target, parse(fh.read())))
                    declared_paths.append(os.path.dirname(target))
                except Invalid as invalid:
                    problems.extend("%s: %s" % (target, p) for p in invalid.problems)
        if problems:
            _report_fail(args, problems)
            return 1

    # Declaring the parts that exist is not the same as declaring every part that
    # can produce a finding. A directory with a dependency manifest and no
    # declaration covering it is outside the process while the repository looks
    # answered — which is what happens when somebody adds one, and nothing else
    # would catch it.
    gaps = uncovered(declared_paths, root)
    if gaps:
        _report_uncovered(args, gaps, len(parts))
        return 1

    _report_parts(args, parts)
    return 0


def _report_uncovered(args, gaps, declared):
    out = sys.stderr
    one = len(gaps) == 1
    print("%d director%s %s a dependency manifest and no declaration covers %s:\n"
          % (len(gaps), "y" if one else "ies", "holds" if one else "hold",
             "it" if one else "them"), file=out)
    for gap in gaps:
        print("  %s" % gap, file=out)
    print("\nA vulnerability is reported against a manifest, so each of these can "
          "produce findings that belong to nobody — while this repository looks "
          "declared, because its %d other part%s %s."
          % (declared, "" if declared == 1 else "s",
             "is" if declared == 1 else "are"), file=out)
    print("\nAdd a flox-info.yaml in each, and list it in %s. Or, if one of the "
          "parts already declared should own it, move that declaration up to the "
          "directory above both." % args.path, file=out)
    _write_summary(args, "### Undeclared parts\n\n%s\n"
                   % "\n".join("- `%s`" % g for g in gaps))


def _report_parts(args, parts):
    if len(parts) == 1 and parts[0][0] == args.path:
        _report_pass(args, parts[0][1])
        return
    lines = ["%d parts declared:" % len(parts)]
    for path, decl in parts:
        lines.append("  %-44s %-16s %s"
                     % (os.path.dirname(path), decl["classification"], decl["aor"]))
    print("\n".join(lines))
    _write_summary(args, "### %d parts declared\n\n%s\n"
                   % (len(parts),
                      "\n".join("- `%s` — %s, %s" % (os.path.dirname(p),
                                                     d["classification"], d["aor"])
                                for p, d in parts)))


def _report_pass(args, decl):
    # Name the component, not the repository. A monorepo declares several, and
    # "floxhub is customer-facing" is both wrong and unhelpful when what passed
    # was src/web-ui.
    subject = decl.get("name") or args.repo
    where = os.path.dirname(args.path)
    if where:
        subject = "%s (%s)" % (subject, where)
    line = "%s is %s, ceiling %s, lifecycle %s, owned by %s." % (
        subject, decl["classification"], decl["max_tier"],
        decl["lifecycle"], decl["aor"])
    print(line)
    if decl["aor"] == UNOWNED:
        print("No Area of Responsibility yet. This passes, and the repository is "
              "reported as unowned until one is named.")
    _write_summary(args, "### Scope declared\n\n%s\n" % line)


def _report_fail(args, problems):
    example = TEMPLATE % {
        "repo": args.repo,
        "classifications": " | ".join(CLASSIFICATIONS),
        "tiers": " | ".join(TIERS),
        "lifecycles": " | ".join(LIFECYCLES),
        "unowned": UNOWNED,
    }
    out = sys.stderr
    print("This repository has not declared its compliance scope.\n", file=out)
    for problem in problems:
        print("  - %s" % problem, file=out)
    print("\nAdd %s to the repository root. A starting point, with the "
          "conservative answers filled in:\n" % args.path, file=out)
    print(example, file=out)
    print(WHY, file=out)

    _write_summary(args, "### Scope not declared\n\n%s\n\n```yaml\n%s```\n\n%s\n" % (
        "\n".join("- %s" % p for p in problems), example, WHY))


def _write_summary(args, markdown):
    if not args.summary:
        return
    with open(args.summary, "a") as fh:
        fh.write(markdown)


if __name__ == "__main__":
    sys.exit(main())
