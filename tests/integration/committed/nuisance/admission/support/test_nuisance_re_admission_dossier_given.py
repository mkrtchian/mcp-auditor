import importlib
import pkgutil

import evals.cve.nuisance.fix_checks as fix_checks


def the_fix_check_package_helpers() -> list[str]:
    """The modules of the fix-check package that define no fixture."""
    names = [
        f"{fix_checks.__name__}.{info.name}" for info in pkgutil.iter_modules(fix_checks.__path__)
    ]
    return [name for name in names if not hasattr(importlib.import_module(name), "FIXTURES")]
