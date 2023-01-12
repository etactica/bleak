# Wrapper for "legacy" environments
from setuptools import setup

setup_kwargs = {
    "package_dir": {
        "bleak":"bleak",
    }
}
setup(**setup_kwargs)
