from __future__ import annotations

import pytest

from kata_forge.spec import SpecError, validate_spec


def test_derivations_match_kata_sn126() -> None:
    spec = validate_spec(subnet_number=126, pack="sn126__poker44", evaluator_id="sn126_poker44")
    assert spec.package == "kata_sn126"
    assert spec.repo_name == "kata-sn126"
    assert spec.slug == "poker44"
    assert spec.class_name == "Poker44Plugin"
    assert spec.singleton == "POKER44_PLUGIN"
    assert spec.mode == "miner"


def test_multiword_slug_camel_cases() -> None:
    spec = validate_spec(subnet_number=44, pack="sn44__my_subnet", evaluator_id="sn44_my")
    assert spec.class_name == "MySubnetPlugin"
    assert spec.singleton == "MY_SUBNET_PLUGIN"
    assert spec.package == "kata_sn44"


def test_name_overrides_slug() -> None:
    spec = validate_spec(subnet_number=7, pack="sn7__foo", evaluator_id="sn7_foo", name="bar")
    assert spec.slug == "bar" and spec.class_name == "BarPlugin"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"subnet_number": 0, "pack": "sn0__x", "evaluator_id": "e"},  # non-positive subnet
        {"subnet_number": 126, "pack": "poker44", "evaluator_id": "sn126_poker44"},  # bad pack shape
        {"subnet_number": 126, "pack": "sn99__poker44", "evaluator_id": "sn126_poker44"},  # number mismatch
        {"subnet_number": 126, "pack": "sn126__Poker44", "evaluator_id": "sn126_poker44"},  # uppercase pack
        {"subnet_number": 126, "pack": "sn126__poker44", "evaluator_id": "Sn126"},  # bad evaluator
        {"subnet_number": 126, "pack": "sn126__poker44", "evaluator_id": "sn126", "mode": "Miner"},  # bad mode
    ],
)
def test_invalid_specs_raise(kwargs) -> None:
    with pytest.raises(SpecError):
        validate_spec(**kwargs)
