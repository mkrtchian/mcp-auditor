"""The fix-check fixtures: each a FixCheckTarget the admission agent writes and the kit driver
runs, with the vulnerable Dockerfile and the exploits committed beside the admission.

Unlike a holdout KitTarget, a FixCheckTarget is never transplanted into an in-repo twin: the fix
check runs outside any audit and the auditor never sees these fixtures. The module imports from
evals.holdout_kit only, which keeps it inside the kit's import closure.

FIX_CHECK_TARGETS is empty until the maintainer's admission session fills it.
"""

from evals.holdout_kit.fix_check import FixCheckTarget

FIX_CHECK_TARGETS: tuple[FixCheckTarget, ...] = ()
