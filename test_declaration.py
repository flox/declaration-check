"""What a pull request diff cannot tell you about the declaration checker.

The checker is the one piece of this process that runs in every repository in the
organisation, and its failure mode is silent: a check that accepts a malformed
declaration reports success, and the register it feeds is wrong in a way nobody
sees until an audit. So these tests cover rejection rather than acceptance — the
cases where passing would be the bug.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import declaration


def decl(classification="customer-facing", tier="auto", lifecycle="active",
         owner="group:linear/aor-59", annotations="", spec_extra=""):
    labels = "\n".join(filter(None, [
        "    flox.dev/classification: %s" % classification if classification else "",
        "    flox.dev/max-tier: %s" % tier if tier else "",
    ]))
    ann = "  annotations:\n%s\n" % annotations if annotations else ""
    return (
        "apiVersion: backstage.io/v1alpha1\n"
        "kind: Component\n"
        "metadata:\n"
        "  name: example\n"
        "  labels:\n%s\n%s"
        "spec:\n"
        "  type: service\n"
        "  lifecycle: %s\n"
        "  owner: %s\n%s" % (labels, ann, lifecycle, owner, spec_extra)
    )


class TestAccepts(unittest.TestCase):

    def test_a_complete_in_scope_declaration(self):
        got = declaration.parse(decl())
        self.assertEqual(got["in_scope"], True)
        self.assertEqual(got["classification"], "customer-facing")
        self.assertEqual(got["exposure"], "customer-facing")
        self.assertEqual(got["max_tier"], "auto")
        self.assertEqual(got["aor"], "group:linear/aor-59")

    def test_out_of_scope_with_a_date(self):
        got = declaration.parse(decl(
            classification="non-production",
            annotations="    flox.dev/expected-production: 2027-01-01"))
        self.assertEqual(got["in_scope"], False)
        self.assertEqual(got["expected_production"], "2027-01-01")

    def test_an_unquoted_date_is_normalised_not_rejected(self):
        """YAML parses a bare ISO date into a date object before we see it.

        Unlike the scope label, a date means the same thing quoted or not, so
        the checker normalises rather than refusing.
        """
        got = declaration.parse(decl(
            classification="non-production",
            annotations="    flox.dev/expected-production: 2027-06-30"))
        self.assertEqual(got["expected_production"], "2027-06-30")

    def test_out_of_scope_that_never_ships(self):
        got = declaration.parse(decl(
            classification="non-production",
            annotations="    flox.dev/expected-production: never"))
        self.assertEqual(got["expected_production"], "never")


class TestRejects(unittest.TestCase):
    """Each of these passing would be a defect that reaches the register."""

    def assertProblem(self, text, fragment):
        with self.assertRaises(declaration.Invalid) as caught:
            declaration.parse(text)
        joined = " ".join(caught.exception.problems)
        self.assertIn(fragment, joined,
                      "expected a problem mentioning %r, got: %s" % (fragment, joined))

    def test_missing_classification(self):
        self.assertProblem(decl(classification=""), "classification must be one of")

    def test_unknown_classification(self):
        self.assertProblem(decl(classification="sort-of-public"),
                           "classification must be one of")

    def test_unknown_lifecycle(self):
        """Backstage accepts any lifecycle; we accept three, so nobody invents a fourth."""
        self.assertProblem(decl(lifecycle="production"), "lifecycle must be one of")

    def test_unknown_tier(self):
        self.assertProblem(decl(tier="automatic"), "max-tier must be one of")

    def test_owner_naming_a_person(self):
        """ADR-005: the declaration references an area, never a person."""
        self.assertProblem(decl(owner="user:default/isaac"), "Area of Responsibility")

    def test_unowned_is_refused_in_scope(self):
        """Out of scope the sentinel defers the question; in scope it dodges it."""
        self.assertProblem(decl(owner=declaration.UNOWNED), "not permitted in scope")

    def test_out_of_scope_without_a_production_date(self):
        """Robin's case: non-production repositories that quietly become production."""
        self.assertProblem(decl(classification="non-production"), "required out of scope")

    def test_out_of_scope_with_an_unparseable_date(self):
        self.assertProblem(
            decl(classification="non-production",
                 annotations="    flox.dev/expected-production: soon"),
            "must be an ISO date")

    def test_not_yaml(self):
        self.assertProblem("{{{", "not valid YAML")

    def test_every_problem_is_reported_at_once(self):
        """Whoever fixes this should need one pass, not four."""
        with self.assertRaises(declaration.Invalid) as caught:
            declaration.parse(decl(classification="nope", tier="nope",
                                   lifecycle="nope", owner="nope"))
        self.assertGreaterEqual(len(caught.exception.problems), 4)


class TestReleaseWorkflows(unittest.TestCase):

    def test_declared_workflows_are_read(self):
        got = declaration.parse(decl(
            annotations="    flox.dev/release-workflows: deploy.yml, mirror.yml"))
        self.assertEqual(got["release_workflows"], ["deploy.yml", "mirror.yml"])

    def test_absent_annotation_means_none(self):
        self.assertEqual(declaration.parse(decl())["release_workflows"], [])


class TestExpectedProduction(unittest.TestCase):

    def test_a_passed_date_surfaces(self):
        import datetime
        d = declaration.parse(decl(
            classification="non-production",
            annotations="    flox.dev/expected-production: 2026-01-01"))
        self.assertTrue(declaration.is_expected_in_production(
            d, today=datetime.date(2026, 10, 13)))

    def test_never_never_surfaces(self):
        d = declaration.parse(decl(
            classification="non-production",
            annotations="    flox.dev/expected-production: never"))
        self.assertFalse(declaration.is_expected_in_production(d))


if __name__ == "__main__":
    unittest.main()


class TestMonorepoLocations(unittest.TestCase):
    """A repository whose parts have different owners declares them separately.

    Backstage's own model: a Location at the root points at a descriptor for each
    part. The alternative — one declaration per repository — forces floxhub's
    nine separately-owned subtrees into a single classification and a single
    automation ceiling, which is simply false about them.
    """

    LOCATION = (
        "apiVersion: backstage.io/v1alpha1\n"
        "kind: Location\n"
        "metadata:\n"
        "  name: example\n"
        "spec:\n"
        "  targets:\n"
        "    - ./src/web-ui/flox-info.yaml\n"
        "    - ./src/web-bff/flox-info.yaml\n"
    )

    def test_targets_are_read_and_normalised(self):
        self.assertEqual(
            declaration.targets(self.LOCATION),
            ["src/web-ui/flox-info.yaml", "src/web-bff/flox-info.yaml"])

    def test_a_component_is_not_a_location(self):
        self.assertIsNone(declaration.targets(decl()))

    def test_a_location_listing_nothing_is_refused(self):
        """It would leave every part undeclared while looking like an answer."""
        empty = self.LOCATION.split("spec:")[0] + "spec:\n  targets: []\n"
        with self.assertRaises(declaration.Invalid) as caught:
            declaration.targets(empty)
        self.assertIn("must list spec.targets", " ".join(caught.exception.problems))

    def test_a_location_pointing_outside_the_repository_is_refused(self):
        """A declaration is evidence about the repository it sits in.

        Backstage allows absolute URLs here. We do not: a target elsewhere could
        change without a reviewed commit in the repository it describes, which is
        the property ADR-001 exists to get.
        """
        external = (self.LOCATION.split("targets:")[0]
                    + "targets:\n    - https://example.com/flox-info.yaml\n")
        with self.assertRaises(declaration.Invalid) as caught:
            declaration.targets(external)
        self.assertIn("not URLs", " ".join(caught.exception.problems))

    def test_a_location_declares_nothing_itself(self):
        with self.assertRaises(declaration.Invalid) as caught:
            declaration.parse(self.LOCATION)
        self.assertIn("points at other descriptors",
                      " ".join(caught.exception.problems))


class TestEveryManifestIsCovered(unittest.TestCase):
    """The rule that makes a monorepo safe to add to.

    Declaring the parts that exist is not the same as declaring every part that
    can produce a finding. Somebody adds a directory with a lockfile and no
    descriptor — the ordinary case, not a malicious one — and nothing else
    catches it: the root Location still validates, because every target it lists
    is still there. The repository looks declared while a part of it is outside
    the process entirely.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def manifest(self, *directories):
        for d in directories:
            full = os.path.join(self.root, d) if d else self.root
            os.makedirs(full, exist_ok=True)
            with open(os.path.join(full, "package-lock.json"), "w") as fh:
                fh.write("{}")

    def test_a_declaration_covers_its_own_directory(self):
        self.manifest("src/web-ui")
        self.assertEqual(declaration.uncovered(["src/web-ui"], self.root), [])

    def test_a_declaration_covers_directories_beneath_it(self):
        """Prefix coverage, the way CODEOWNERS works."""
        self.manifest("src/openfga/reconcile")
        self.assertEqual(declaration.uncovered(["src/openfga"], self.root), [])

    def test_a_root_declaration_covers_everything(self):
        """Which is why this rule costs a single-component repository nothing."""
        self.manifest("", "src/a", "src/b/c")
        self.assertEqual(declaration.uncovered([""], self.root), [])

    def test_an_undeclared_manifest_directory_is_reported(self):
        self.manifest("src/web-ui", "src/newthing")
        self.assertEqual(declaration.uncovered(["src/web-ui"], self.root),
                         ["src/newthing"])

    def test_a_sibling_does_not_cover_its_neighbour(self):
        """src/openfga/reconcile must not be taken to cover src/openfga/other."""
        self.manifest("src/openfga/reconcile", "src/openfga/other")
        self.assertEqual(
            declaration.uncovered(["src/openfga/reconcile"], self.root),
            ["src/openfga/other"])

    def test_vendored_trees_are_not_swept(self):
        """node_modules is somebody else's dependencies, and nothing reports on it."""
        self.manifest("node_modules/left-pad", "src/web-ui")
        self.assertEqual(declaration.uncovered(["src/web-ui"], self.root), [])


class TestStandsAlone(unittest.TestCase):
    """The checker has to work from a repository that holds only this file.

    The checks run in every flox repository, and a required workflow may only be
    required from a repository at least as visible as the one it runs on — so the
    checker ships from a public repository while the Sprinto side stays private.
    That split holds only while `declaration.py` imports nothing of ours. A diff
    adding `import register` back would look harmless and would break the check
    in every repository at once, which is why this is asserted rather than
    remembered.
    """

    def test_declaration_imports_with_nothing_else_of_ours_present(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(declaration.__file__)),
                                 "declaration.py"),
                    os.path.join(root, "declaration.py"))
        out = subprocess.run(
            [sys.executable, "-c", "import declaration; print(declaration.TIERS)"],
            cwd=root, capture_output=True, text=True,
            env=dict(os.environ, PYTHONPATH=root, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("auto", out.stdout)


class TestActionsEcosystem(unittest.TestCase):
    """GitHub Actions is an ecosystem, and alerts from it need an owner too.

    This was the gap that let floxhub pass while three alertable directories had
    no declaration behind them: the manifest list knew about lockfiles and said
    nothing about workflows or action definitions. A repository could be fully
    declared and still route an alert nowhere.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, relative):
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write("# test\n")

    def test_a_workflow_directory_carries_dependencies(self):
        """Dependabot's github-actions ecosystem raises findings against these."""
        self.write(".github/workflows/ci.yml")
        self.assertIn(".github/workflows",
                      declaration.manifest_directories(self.root))

    def test_an_empty_workflow_directory_does_not(self):
        os.makedirs(os.path.join(self.root, ".github/workflows"))
        self.assertNotIn(".github/workflows",
                         declaration.manifest_directories(self.root))

    def test_a_composite_action_carries_dependencies(self):
        """Its `uses:` references are pinned third-party code."""
        self.write(".github/actions/common-setup/action.yml")
        self.assertIn(".github/actions/common-setup",
                      declaration.manifest_directories(self.root))
        self.write("tools/release/action.yaml")
        self.assertIn("tools/release",
                      declaration.manifest_directories(self.root))

    def test_yaml_elsewhere_is_configuration_not_a_manifest(self):
        """Only the workflow directory is special. A .yml in src/ is config, and
        treating every yaml as a manifest would demand a declaration beside
        every settings file in the repository."""
        self.write("src/thing/config.yml")
        self.write("deploy/values.yaml")
        found = declaration.manifest_directories(self.root)
        self.assertNotIn("src/thing", found)
        self.assertNotIn("deploy", found)

    def test_a_declaration_at_dotgithub_covers_both(self):
        """Which is what lets one descriptor own CI rather than three."""
        self.write(".github/workflows/ci.yml")
        self.write(".github/actions/common-setup/action.yml")
        self.assertEqual(declaration.uncovered([".github"], self.root), [])

    def test_without_that_declaration_both_are_reported(self):
        self.write(".github/workflows/ci.yml")
        self.write(".github/actions/common-setup/action.yml")
        self.assertEqual(
            declaration.uncovered(["src/web-ui"], self.root),
            [".github/actions/common-setup", ".github/workflows"])


class TestTargetPathsWithLeadingDots(unittest.TestCase):
    """`./.github/x` must not become `github/x`.

    It did. The normalisation was `lstrip("./")`, which takes a set of
    characters rather than a prefix, so it removed the dot of the dotted
    directory as well. The check then reported a target that does not exist,
    while the directory it was meant to cover went unchecked — a false failure
    hiding a real gap, which is the worst of both.
    """

    def location(self, *targets):
        return ("apiVersion: backstage.io/v1alpha1\n"
                "kind: Location\n"
                "metadata:\n  name: t\n"
                "spec:\n  type: url\n  targets:\n"
                + "".join("    - %s\n" % t for t in targets))

    def test_a_dotted_directory_keeps_its_dot(self):
        self.assertEqual(
            declaration.targets(self.location("./.github/flox-info.yaml")),
            [".github/flox-info.yaml"])

    def test_a_dotted_directory_without_a_prefix_is_unchanged(self):
        self.assertEqual(
            declaration.targets(self.location(".github/flox-info.yaml")),
            [".github/flox-info.yaml"])

    def test_an_ordinary_relative_prefix_is_still_removed(self):
        self.assertEqual(
            declaration.targets(self.location("./src/web-ui/flox-info.yaml")),
            ["src/web-ui/flox-info.yaml"])

    def test_repeated_prefixes_are_removed_a_segment_at_a_time(self):
        self.assertEqual(
            declaration.targets(self.location("././.github/x/flox-info.yaml")),
            [".github/x/flox-info.yaml"])
