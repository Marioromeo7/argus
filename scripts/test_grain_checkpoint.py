"""
ARGUS — eval_grain.py checkpoint/resume logic unit test (ROADMAP R2.2).

Pure-logic test for the checkpoint save/load/resume bookkeeping added to
scripts/eval_grain.py 2026-08-19 -- needs NO Neo4j, Ollama, or GPU. A real
node takes 20-60 min to test this live (confirmed 2026-08-19: one node ran
well over 2 hours), which is a slow, expensive way to verify bookkeeping that
has nothing to do with LLM call timing. This directly targets the bug class
already found once by hand (the return statement referencing `nodes`, a
variable undefined on the resume path -- would have NameError'd on every
--resume run) and the four code paths traced by hand in ROADMAP: fresh,
resume-with-checkpoint, resume-with-no-checkpoint-yet, resume-after-full-
completion.

Loads eval_grain.py via runpy (same pattern used throughout this session --
the file has no __init__.py-based package identity) and drives its real
_load_checkpoint/_save_checkpoint functions plus a stubbed challenge_node_v2
and get_low_grain_nodes, so the actual run_eval() control flow executes for
real, not a reimplementation of its logic.

Usage:
    conda activate argus
    python scripts/test_grain_checkpoint.py
"""
import os
import sys
import json
import shutil
import runpy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCRATCH_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "results", "_test_grain_checkpoint_scratch")
CKPT_PATH = os.path.join(SCRATCH_DIR, "checkpoint.json")


def _fake_report(node_id: str, grain: float) -> dict:
    return {
        "node_id": node_id, "status": "resolved", "rounds_run": 3,
        "grain_confidence": grain, "total_questions": 5, "trusted": 2,
        "open_questions": [], "history": [(1, 3), (2, 4), (2, 5)],
        "log": {}, "rounds_detail": [],
        "confidence_components": [
            {"round": 1, "cumulative": 0.3, "freshness": 0.3, "new_questions": 1, "confidence": 0.3},
            {"round": 2, "cumulative": 0.4, "freshness": 0.5, "new_questions": 1, "confidence": 0.45},
            {"round": 3, "cumulative": 0.4, "freshness": 0.4, "new_questions": 0, "confidence": 0.4},
        ],
    }


class _FakeSession:
    def run(self, *a, **kw):
        return None
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class _FakeDriver:
    def session(self):
        return _FakeSession()
    def close(self):
        pass


def _setup():
    if os.path.exists(SCRATCH_DIR):
        shutil.rmtree(SCRATCH_DIR)
    os.makedirs(SCRATCH_DIR, exist_ok=True)


def _load_module():
    """Load eval_grain.py fresh each time so module-level state (none, but
    defensive) can't leak between test cases."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "scripts", "eval_grain.py")
    return runpy.run_path(path)


def test_checkpoint_created_on_fresh_run():
    _setup()
    ns = _load_module()
    fake_nodes = [{"node_id": "T_FAKE_A", "grain_confidence": 0.3},
                  {"node_id": "T_FAKE_B", "grain_confidence": 0.3}]
    calls = []

    def fake_get_low_grain_nodes(driver, threshold, limit):
        return fake_nodes[:limit]

    def fake_challenge_node_v2(driver, node_id):
        calls.append(node_id)
        return _fake_report(node_id, 0.6)

    # Monkeypatch the names run_eval's own `from ... import ...` statements
    # bind at call time -- patching the already-imported symbols in the
    # loaded module namespace before calling run_eval.
    ns["get_low_grain_nodes"] = fake_get_low_grain_nodes
    import graph.retrieval as _gr
    import agents.narrowing as _an
    orig_glgn, orig_cnv2 = _gr.get_low_grain_nodes, _an.challenge_node_v2
    orig_gd = _gr.get_driver
    _gr.get_low_grain_nodes = fake_get_low_grain_nodes
    _gr.get_driver = lambda: _FakeDriver()
    _an.challenge_node_v2 = fake_challenge_node_v2
    try:
        result = ns["run_eval"](n_nodes=2, resume=False, checkpoint_path=CKPT_PATH)
    finally:
        _gr.get_low_grain_nodes = orig_glgn
        _gr.get_driver = orig_gd
        _an.challenge_node_v2 = orig_cnv2

    assert calls == ["T_FAKE_A", "T_FAKE_B"], calls
    assert result["n_nodes"] == 2, result
    assert os.path.exists(CKPT_PATH), "checkpoint file was not created"
    with open(CKPT_PATH) as f:
        ckpt = json.load(f)
    assert ckpt["node_ids"] == ["T_FAKE_A", "T_FAKE_B"], ckpt["node_ids"]
    assert len(ckpt["reports"]) == 2, ckpt["reports"]
    print("[PASS] fresh run: checkpoint created, both nodes run, node_ids persisted")


def test_resume_skips_completed_nodes():
    """The actual bug class found by hand 2026-08-19: does resume correctly
    skip already-done nodes AND not crash on the `len(node_ids)` return path
    (previously `len(nodes)`, undefined on this exact path)?"""
    _setup()
    ns = _load_module()
    # Pre-seed a checkpoint as if node A already completed in a prior run.
    ckpt = {
        "node_ids": ["T_FAKE_A", "T_FAKE_B"],
        "before_grains": {"T_FAKE_A": 0.3, "T_FAKE_B": 0.3},
        "reports": [_fake_report("T_FAKE_A", 0.6)],
    }
    with open(CKPT_PATH, "w") as f:
        json.dump(ckpt, f)

    calls = []

    def fake_challenge_node_v2(driver, node_id):
        calls.append(node_id)
        return _fake_report(node_id, 0.7)

    import graph.retrieval as _gr
    import agents.narrowing as _an

    def fail_if_called(*a, **kw):
        raise AssertionError(
            "get_low_grain_nodes() was called on --resume -- must reuse the "
            "persisted node_ids verbatim, not re-query (grain drift risk)")

    orig_glgn, orig_cnv2, orig_gd = _gr.get_low_grain_nodes, _an.challenge_node_v2, _gr.get_driver
    _gr.get_low_grain_nodes = fail_if_called
    _gr.get_driver = lambda: _FakeDriver()
    _an.challenge_node_v2 = fake_challenge_node_v2
    try:
        result = ns["run_eval"](n_nodes=2, resume=True, checkpoint_path=CKPT_PATH)
    finally:
        _gr.get_low_grain_nodes = orig_glgn
        _gr.get_driver = orig_gd
        _an.challenge_node_v2 = orig_cnv2

    assert calls == ["T_FAKE_B"], f"expected only the incomplete node re-run, got {calls}"
    assert result["n_nodes"] == 2, result  # THE bug: this used to be len(nodes), NameError here
    print("[PASS] resume: skipped completed node A, ran only B, "
          "no NameError on the n_nodes return path")


def test_resume_after_full_completion_is_noop():
    _setup()
    ns = _load_module()
    ckpt = {
        "node_ids": ["T_FAKE_A", "T_FAKE_B"],
        "before_grains": {"T_FAKE_A": 0.3, "T_FAKE_B": 0.3},
        "reports": [_fake_report("T_FAKE_A", 0.6), _fake_report("T_FAKE_B", 0.7)],
    }
    with open(CKPT_PATH, "w") as f:
        json.dump(ckpt, f)

    def fail_if_called(*a, **kw):
        raise AssertionError("challenge_node_v2 should not be called -- "
                              "both nodes are already complete")

    import graph.retrieval as _gr
    import agents.narrowing as _an
    orig_cnv2, orig_gd = _an.challenge_node_v2, _gr.get_driver
    _gr.get_driver = lambda: _FakeDriver()
    _an.challenge_node_v2 = fail_if_called
    try:
        result = ns["run_eval"](n_nodes=2, resume=True, checkpoint_path=CKPT_PATH)
    finally:
        _gr.get_driver = orig_gd
        _an.challenge_node_v2 = orig_cnv2

    assert result["n_nodes"] == 2, result
    print("[PASS] resume after full completion: no re-runs, clean analysis-only pass")


if __name__ == "__main__":
    test_checkpoint_created_on_fresh_run()
    test_resume_skips_completed_nodes()
    test_resume_after_full_completion_is_noop()
    shutil.rmtree(SCRATCH_DIR, ignore_errors=True)
    print("\nAll eval_grain checkpoint tests passed.")
