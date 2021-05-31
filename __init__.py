__version__ = "unknown"
try:
    from ._version import __version__
except ImportError:
    pass
quiet_pyflakes=[__version__]

