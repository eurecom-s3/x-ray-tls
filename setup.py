"""
Setup file
"""

from distutils.core import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension("src.memdiff.memdiffer", ["src/memdiff/memdiffer.py"]),
    Extension("src.keyfinder.finder", ["src/keyfinder/finder.py"]),
    Extension("src.network_analyzer.network", ["src/network_analyzer/network.py"]),
    # Extension("src.dumper.handshake_detector", ["src/dumper/handshake_detector.py"]),  TODO
    Extension("src.baseline.entropy_filter", ["src/baseline/entropy_filter.py"]),
]

setup(
    name="TLS traffic analyzer",
    version="1.0.0",
    ext_modules = cythonize(
        extensions,
        compiler_directives={'language_level' : "3"}
    )
)
