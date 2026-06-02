#!/usr/bin/env python3
"""Correctness-only integration tests for the runtime evidence prototype.

This is a Docker + sudo + eBPF integration smoke test, so it intentionally
stays outside `cargo test`.

Expected behaviour:
- /echo produces /usr/bin/echo evidence and verifier ACCEPTs.
- /bad produces /usr/bin/id evidence and verifier REJECTs.
"""

from __future__ import annotations

import signal
import sys
from dataclasses import dataclass

from integration_lib import IntegrationFailure, RuntimeHarness, Settings, log


@dataclass(frozen=True)
class IntegrationCase:
    name: str
    title: str
    http_paths: tuple[str, ...]
    evidence_must_contain: tuple[str, ...]
    expect_accept: bool


DEFAULT_CASES: tuple[IntegrationCase, ...] = (
    IntegrationCase(
        name="echo",
        title="scoped /echo case",
        http_paths=("/ping", "/echo"),
        evidence_must_contain=("/usr/bin/echo",),
        expect_accept=True,
    ),
    IntegrationCase(
        name="bad",
        title="scoped /bad case",
        http_paths=("/bad",),
        evidence_must_contain=("/usr/bin/id",),
        expect_accept=False,
    ),
)


class IntegrationTestRunner(RuntimeHarness):
    def __init__(self, settings: Settings, cases: tuple[IntegrationCase, ...]) -> None:
        super().__init__(settings)
        self.cases = cases

    def run(self) -> int:
        try:
            self.check_privileges()
            self.build()
            self.clean_integration_logs()

            self.workload.start()

            for case in self.cases:
                self.run_case(case)

            log("V1 integration tests passed")
            return 0
        except KeyboardInterrupt:
            print("Interrupted", file=sys.stderr)
            return 130
        except IntegrationFailure as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            self.monitor.print_log_tail()
            return 1
        finally:
            self.cleanup()

    def run_case(self, case: IntegrationCase) -> None:
        log(f"== {case.title} ==")

        paths = self.case_paths(case.name)
        self.clean_case(paths)
        self.write_case_collector_config(paths)

        started_at = self.monitor.start(paths)
        try:
            for path in case.http_paths:
                self.workload.get(path)
        finally:
            self.monitor.stop()

        self.assert_fresh_evidence(paths, started_at)

        for expected in case.evidence_must_contain:
            self.assert_evidence_contains(paths, expected)

        self.expect_verifier(paths, expect_accept=case.expect_accept)

        log(f"PASS: {case.title}")


def main() -> int:
    settings = Settings.from_env()
    runner = IntegrationTestRunner(settings, DEFAULT_CASES)
    return runner.run()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
