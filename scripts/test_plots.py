"""Hermetic tests for the evaluation plotting layer.

The pure `extract_*` / table / stats logic is tested against synthetic JSON shaped
like the real harness output — no matplotlib needed. A render smoke test is skipped
when matplotlib is absent, so the suite stays green everywhere (e.g. the dev sandbox)
while still exercising the matplotlib path on hosts that have it.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import plot_security
import plot_tpm_cost
import plot_tpm_workload
import plotlib
import run_tpm_cost_experiments as tpm_harness

try:
    import matplotlib  # noqa: F401

    HAVE_MPL = True
except Exception:  # pragma: no cover - depends on the host
    HAVE_MPL = False


SECURITY_FIXTURE = {
    "environment": {
        "git_commit": "abcdef123456",
        "cpu_governor": "performance",
        "monitor_build_mode": "release",
        "captured_utc": "2026-06-13T00:00:00Z",
    },
    "tamper": {
        "detected_count": 2,
        "precise_count": 2,
        "total_count": 2,
        "cases": [
            {
                "name": "edit-exe-path",
                "guarantee": "per-event hash",
                "decision": "INVALID-EVIDENCE",
                "detected": True,
                "precise": True,
                "primary_check": "event_hashes_valid",
                "failed_checks": ["event_hashes_valid", "software_chain_valid"],
            },
            {
                "name": "delete-record",
                "guarantee": "sequence contiguity",
                "decision": "INVALID-EVIDENCE",
                "detected": True,
                "precise": True,
                "primary_check": "sequence_valid",
                "failed_checks": ["counts_valid", "sequence_valid", "software_chain_valid"],
            },
        ],
    },
}


def tpm_fixture() -> dict:
    projection = tpm_harness.project_extend_costs(2.0, [1000], [0.0, 0.5, 1.0])
    return {
        "environment": {"git_commit": "abc1234567", "cpu_governor": "performance"},
        "extend_cost": {
            "raw_per_extend_ms": [1.9, 2.0, 2.1, 2.0],
            "per_extend_ms": {"median": 2.0},
            "per_extend_ms_ci": {"point": 2.0, "low": 1.8, "high": 2.2},
            "tcti": "swtpm:host=127.0.0.1,port=2321",
        },
        "model": {
            "extend_cost_ms": 2.0,
            "projection": projection,
            "decision_rule": "…",
        },
    }


class PlotlibTest(unittest.TestCase):
    def test_median_ci_asymmetric(self) -> None:
        point, lo, hi = plotlib.median_ci({"median": 2.0}, {"point": 2.0, "low": 1.8, "high": 2.2})
        self.assertEqual(point, 2.0)
        self.assertAlmostEqual(lo, 0.2)
        self.assertAlmostEqual(hi, 0.2)

    def test_median_ci_without_ci_falls_back_to_zero_error(self) -> None:
        self.assertEqual(plotlib.median_ci({"median": 5.0}, {}), (5.0, 0.0, 0.0))

    def test_footnote_carries_commit_and_governor(self) -> None:
        fn = plotlib.footnote(SECURITY_FIXTURE["environment"])
        self.assertIn("abcdef1234", fn)
        self.assertIn("governor=performance", fn)
        self.assertIn("release", fn)

    def test_write_table_emits_csv_and_escaped_latex(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            csv_path, tex_path = plotlib.write_table("t", ["a", "b"], [[1, 2], ["x_y", 3]], figure_dir=Path(d))
            self.assertIn("a,b", csv_path.read_text())
            tex = tex_path.read_text()
            self.assertIn(r"\toprule", tex)
            self.assertIn(r"x\_y", tex)  # underscore escaped for LaTeX


class SecurityExtractTest(unittest.TestCase):
    def test_matrix_encodes_primary_fired_and_blank(self) -> None:
        data = plot_security.extract_tamper_matrix(SECURITY_FIXTURE)
        idx = data["checks"].index
        m = data["matrix"]
        self.assertEqual(len(data["checks"]), 16)
        # edit-exe-path: primary check outlined, a second check fired, the rest blank.
        self.assertEqual(m[0][idx("event_hashes_valid")], plot_security.PRIMARY_FIRED)
        self.assertEqual(m[0][idx("software_chain_valid")], plot_security.FIRED)
        self.assertEqual(m[0][idx("schema_valid")], plot_security.NOT_FIRED)
        # delete-record: defence-in-depth — three checks fire, sequence is primary.
        self.assertEqual(m[1][idx("sequence_valid")], plot_security.PRIMARY_FIRED)
        self.assertEqual(m[1][idx("counts_valid")], plot_security.FIRED)
        self.assertEqual(data["summary"], {"detected": 2, "precise": 2, "total": 2})

    def test_table_rows(self) -> None:
        header, rows = plot_security.tamper_table(SECURITY_FIXTURE)
        self.assertEqual(header[0], "case")
        self.assertEqual([r[0] for r in rows], ["edit-exe-path", "delete-record"])


class TpmExtractTest(unittest.TestCase):
    def test_saving_curve_matches_the_model(self) -> None:
        curve = plot_tpm_cost.extract_saving_curve(tpm_fixture())
        self.assertEqual(curve["fractions"], [0.0, 0.5, 1.0])
        self.assertEqual(curve["extends"]["policy-triggered"], [2, 502, 1002])
        self.assertEqual(curve["extends"]["extend-everything"], [1002, 1002, 1002])
        self.assertEqual(curve["saving_extends"], [1000, 500, 0])

    def test_saving_table_has_a_row_per_fraction(self) -> None:
        _, rows = plot_tpm_cost.saving_table(plot_tpm_cost.extract_saving_curve(tpm_fixture()))
        self.assertEqual(len(rows), 3)

    def test_overhead_table_is_extends_scaled_to_seconds(self) -> None:
        # cost=2 ms; N=1000 => extend-everything = 1002 extends = 2.004 s flat.
        # The avoided overhead is (extend-everything - policy-triggered) in seconds.
        header, rows = plot_tpm_cost.overhead_table(plot_tpm_cost.extract_saving_curve(tpm_fixture()))
        self.assertEqual(header[-1], "overhead_avoided_s")
        self.assertEqual(len(rows), 3)
        self.assertEqual([r[3] for r in rows], ["2.004", "2.004", "2.004"])  # extend-everything flat
        self.assertEqual([r[4] for r in rows], ["2.000", "1.000", "0.000"])  # avoided -> 0 at s/N=1

    def test_overhead_vs_n_sweeps_events_at_chosen_fraction(self) -> None:
        proj = tpm_harness.project_extend_costs(2.0, [100, 1000], [0.05])
        vs_n = plot_tpm_cost.extract_overhead_vs_n({"model": {"projection": proj}}, fraction=0.05)
        self.assertAlmostEqual(vs_n["fraction"], 0.05)
        self.assertEqual(vs_n["events"], [100, 1000])
        # cost=2 ms: N=100 -> extend-everything=102 extends=204 ms; N=1000 -> 1002=2004 ms.
        self.assertEqual(vs_n["wall_ms"]["extend-everything"], [204.0, 2004.0])
        self.assertEqual(vs_n["wall_ms"]["final-summary"], [4.0, 4.0])  # 2 fixed extends, flat

    def test_contention_extract_uses_median_throughput(self) -> None:
        result = {
            "contention": {
                "results": [
                    {"concurrency": 1, "per_extend_ms": {"median": 4.0, "p95": 4.5, "p99": 5.0},
                     "per_extend_ms_ci": {"low": 3.8, "high": 4.2}, "throughput_per_s": [200.0, 210.0, 190.0]},
                    {"concurrency": 8, "per_extend_ms": {"median": 8.0, "p95": 50.0, "p99": 900.0},
                     "per_extend_ms_ci": {"low": 7.0, "high": 9.0}, "throughput_per_s": [300.0, 320.0, 280.0]},
                ]
            }
        }
        data = plot_tpm_cost.extract_contention(result)
        self.assertEqual(data["concurrency"], [1, 8])
        self.assertEqual(data["median"], [4.0, 8.0])
        self.assertEqual(data["p99"], [5.0, 900.0])
        self.assertEqual(data["throughput"], [200.0, 300.0])  # median across the 3 trials
        self.assertEqual(data["base_throughput"], 200.0)

    def test_extract_extend_cost_present_and_absent(self) -> None:
        self.assertIsNotNone(plot_tpm_cost.extract_extend_cost(tpm_fixture()))
        self.assertIsNone(plot_tpm_cost.extract_extend_cost({"model": {}}))


def _write_tpmrps(d: Path, mode: str, rps: int, drops, caps, exts) -> None:
    """Write a `tpmrps_<mode>_r<rps>_*.json` shaped like the FastAPI harness output."""
    import json

    trials = []
    for i, (dr, cap, ex) in enumerate(zip(drops, caps, exts), 1):
        tpm = {} if ex is None else {"event_extend_count": ex}
        trials.append({
            "trial": i,
            "evidence": {
                "dropped_events": dr,
                "event_count": cap,
                "monitor_summary": {"tpm": tpm},
            },
        })
    payload = {
        "environment": {"git_commit": "abc1234567", "cpu_governor": "powersave"},
        "aggregate": {"scoped": {
            "median_throughput_rps": float(rps) - 0.1,
            "total_dropped_events": sum(drops),
            "max_dropped_events": max(drops),
        }},
        "trial_results": {"scoped": trials},
    }
    (d / f"tpmrps_{mode}_r{rps}_20260620T000000Z.json").write_text(json.dumps(payload))


def _seed_rate_sweep(d: Path) -> None:
    for rps in (50, 100, 200, 400, 800):
        _write_tpmrps(d, "final_summary", rps, [0, 0, 0], [rps * 10] * 3, [0, 0, 0])
        _write_tpmrps(d, "policy_triggered", rps, [0, 0, 0], [rps * 10] * 3, [0, 0, 0])
    # extend-everything: clean until the swtpm ceiling, knee at 400, blinded at 800.
    _write_tpmrps(d, "extend_everything", 50, [0, 0, 0], [500] * 3, [510, 510, 510])
    _write_tpmrps(d, "extend_everything", 100, [0, 0, 0], [1000] * 3, [1010, 1010, 1010])
    _write_tpmrps(d, "extend_everything", 200, [0, 0, 0], [2000] * 3, [2010, 2010, 2010])
    _write_tpmrps(d, "extend_everything", 400, [1140, 0, 0], [2870, 4000, 4000], [2870, None, None])
    _write_tpmrps(d, "extend_everything", 800, [5352, 5469, 5283], [2658, 2541, 2727], [None, None, None])


class RateSweepTests(unittest.TestCase):
    def test_drops_diverge_only_for_extend_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _seed_rate_sweep(d)
            data = plot_tpm_workload.extract_rate_sweep(d)
            ee = data["series"]["extend_everything"]
            self.assertEqual(ee["rps"], [50, 100, 200, 400, 800])
            self.assertEqual(ee["drops_mean"][:3], [0.0, 0.0, 0.0])  # flat under the ceiling
            self.assertEqual(ee["drops_lo"][3], 0.0)  # knee: one trial drops, two don't
            self.assertEqual(ee["drops_hi"][3], 1140.0)
            self.assertGreater(ee["drops_mean"][-1], 5000)  # blinded at 800 rps
            for tag in ("final_summary", "policy_triggered"):
                self.assertEqual(sum(data["series"][tag]["drops_mean"]), 0)

    def test_loss_pct_is_drops_over_total_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _seed_rate_sweep(d)
            data = plot_tpm_workload.extract_rate_sweep(d)
            # 800 rps: 16104 dropped / (16104 + 7926 captured) = 67%.
            self.assertAlmostEqual(data["series"]["extend_everything"]["loss_pct"][-1], 67.0, delta=1.0)
            self.assertEqual(data["series"]["final_summary"]["loss_pct"][-1], 0.0)

    def test_extends_none_when_unfinalised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _seed_rate_sweep(d)
            data = plot_tpm_workload.extract_rate_sweep(d)
            ee = data["series"]["extend_everything"]
            self.assertEqual(ee["extends"][2], 2010)  # measured where finalised
            self.assertEqual(ee["extends"][3], 2870)  # median of the one finalised trial
            self.assertIsNone(ee["extends"][4])  # all trials failed open at 800 rps

    def test_table_has_a_row_per_mode_and_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _seed_rate_sweep(d)
            header, rows = plot_tpm_workload.rate_sweep_table(plot_tpm_workload.extract_rate_sweep(d))
            self.assertEqual(header[0], "mode")
            self.assertEqual(len(rows), 15)  # 3 modes x 5 rates
            self.assertIn("n/a", [r[3] for r in rows])  # extends absent at high load


@unittest.skipUnless(HAVE_MPL, "matplotlib not installed")
class RenderSmokeTest(unittest.TestCase):
    def test_renders_non_empty_pdfs(self) -> None:
        import warnings

        import matplotlib

        with tempfile.TemporaryDirectory() as d, warnings.catch_warnings():
            # Treat matplotlib API deprecations as failures — a deprecated call
            # (e.g. boxplot(vert=)) would otherwise pass silently until removed.
            warnings.simplefilter("error", matplotlib.MatplotlibDeprecationWarning)
            out = Path(d)
            plot_security.render_tamper_matrix(
                plot_security.extract_tamper_matrix(SECURITY_FIXTURE),
                SECURITY_FIXTURE["environment"],
                figure_dir=out,
            )
            self.assertGreater((out / "f_s2_tamper_matrix.pdf").stat().st_size, 0)
            plot_tpm_cost.render_saving_curve(
                plot_tpm_cost.extract_saving_curve(tpm_fixture()), None, figure_dir=out
            )
            self.assertGreater((out / "f_p4b_tpm_saving.pdf").stat().st_size, 0)
            plot_tpm_cost.render_overhead_curve(
                plot_tpm_cost.extract_saving_curve(tpm_fixture()), None, figure_dir=out
            )
            self.assertGreater((out / "f_p4c_tpm_overhead_line.pdf").stat().st_size, 0)
            # The 2x2 multi-panel figure (the one wired into the report).
            plot_tpm_cost.render_overhead_panels(
                plot_tpm_cost.extract_saving_curve(tpm_fixture()),
                plot_tpm_cost.extract_overhead_vs_n(tpm_fixture()),
                None,
                figure_dir=out,
            )
            self.assertGreater((out / "f_p4c_tpm_overhead.pdf").stat().st_size, 0)
            plot_tpm_cost.render_contention(
                plot_tpm_cost.extract_contention({
                    "contention": {"results": [
                        {"concurrency": 1, "per_extend_ms": {"median": 4.0, "p95": 4.5, "p99": 5.0},
                         "per_extend_ms_ci": {"low": 3.8, "high": 4.2}, "throughput_per_s": [200.0]},
                        {"concurrency": 8, "per_extend_ms": {"median": 8.0, "p95": 50.0, "p99": 900.0},
                         "per_extend_ms_ci": {"low": 7.0, "high": 9.0}, "throughput_per_s": [300.0]},
                    ]}
                }),
                None,
                figure_dir=out,
            )
            self.assertGreater((out / "f_p4d_tpm_contention.pdf").stat().st_size, 0)
            # Cover the boxplot path too (F-P4a) — this is where the deprecated
            # boxplot(vert=) bug hid because the smoke test never rendered it.
            cost = plot_tpm_cost.extract_extend_cost(tpm_fixture())
            plot_tpm_cost.render_extend_cost(cost, None, figure_dir=out)
            self.assertGreater((out / "f_p4a_extend_cost.pdf").stat().st_size, 0)
            # F-P4f: the FastAPI rate-sweep contention figure.
            _seed_rate_sweep(out)
            plot_tpm_workload.render_rate_sweep(
                plot_tpm_workload.extract_rate_sweep(out), figure_dir=out
            )
            self.assertGreater((out / "f_p4f_tpm_rate_sweep.pdf").stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
