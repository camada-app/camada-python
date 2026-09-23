# The SDK's wire identity (SDK-03): x-camada-sdk: <package>/<version>. This literal is the
# single source: hatch reads it at build, so importlib.metadata agrees with it, and the sibling
# drift guards (camada-backend, camada-web, camada-mkt) parse this file the way they parse a
# package.json. Plain X.Y.Z only: the analyst's SDK_RE drops anything PEP 440 adds.
__version__ = "0.2.1"
SDK_ID = f"@camada/python/{__version__}"
