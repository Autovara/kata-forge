"""kata-forge -- the scaffolder that generates ``kata-sn<N>`` subnet plugins.

Templatizes the hand-built ``kata-sn126`` so onboarding a subnet is scaffold + fill the four
subnet-specific methods. Design & progress: ``kata-forge-plan.md``.
"""

from __future__ import annotations

from kata_forge.spec import SubnetSpec, validate_spec

__all__ = ["SubnetSpec", "validate_spec"]
