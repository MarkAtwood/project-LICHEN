# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the /deaddrop SCHC rule provision (spec/appendix-schc.md A.4.1).

The provision allocates no dedicated rule IDs: /deaddrop reuses the existing
rules 0/1/5/6. These tests pin the binding (POSTs OSCORE-only via rules 5/6,
GETs via 5/6 or 0/1) and assert the registry + descriptor hash are unchanged
by the provision.
"""

from __future__ import annotations

from lichen.schc.rules import (
    DEADDROP_GET_RULES,
    DEADDROP_POST_RULES,
    GLOBAL_COAP_RULE,
    GLOBAL_OSCORE_RULE,
    LINK_LOCAL_COAP_RULE,
    LINK_LOCAL_OSCORE_RULE,
    RULES,
    rule_set_v3_descriptor_hash,
)

# The pinned descriptor hash from test/vectors/schc_compression.json (registry
# category). The deaddrop provision MUST NOT change it (no new rule IDs).
_PINNED_DESCRIPTOR_HASH = None  # resolved from the vector at test time


def _pinned_hash() -> str:
    import json
    from pathlib import Path

    repo = Path(__file__).resolve().parents[3]
    data = json.loads((repo / "test/vectors/rule_versioning.json").read_text())
    for vec in data["vectors"]:
        if vec.get("category") == "registry" and "descriptor_hash" in vec:
            return vec["descriptor_hash"]
    raise AssertionError("no registry descriptor_hash vector in rule_versioning.json")


class TestDeaddropRuleProvision:
    def test_post_rules_are_oscore_only(self) -> None:
        """POSTs (writes) MUST use OSCORE rules 5/6 (spec 18.9 mandatory)."""
        assert DEADDROP_POST_RULES == (5, 6)
        assert LINK_LOCAL_OSCORE_RULE.rule_id in DEADDROP_POST_RULES
        assert GLOBAL_OSCORE_RULE.rule_id in DEADDROP_POST_RULES
        # Plaintext rules MUST NOT be accepted for writes.
        assert LINK_LOCAL_COAP_RULE.rule_id not in DEADDROP_POST_RULES
        assert GLOBAL_COAP_RULE.rule_id not in DEADDROP_POST_RULES

    def test_get_rules_permit_plaintext_public_reads(self) -> None:
        """GETs allow OSCORE (5/6) and plaintext (0/1) for public drops."""
        assert DEADDROP_GET_RULES == (5, 6, 0, 1)

    def test_all_provisioned_rules_in_registry(self) -> None:
        """Every provisioned rule ID resolves in the V3 registry."""
        for rule_id in DEADDROP_GET_RULES:
            assert rule_id in RULES, f"rule {rule_id} missing from registry"

    def test_no_dedicated_deaddrop_rule_ids(self) -> None:
        """The provision allocates no new rule IDs (registry unchanged)."""
        assert set(RULES) == {0, 1, 2, 3, 4, 5, 6, 255}

    def test_descriptor_hash_unchanged(self) -> None:
        """Descriptor hash matches the pinned vector (no registry drift)."""
        assert f"{rule_set_v3_descriptor_hash():016x}" == _pinned_hash()
