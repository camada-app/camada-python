# The SDK's wire identity (SDK-03): x-camada-sdk: <package>/<version>. This literal is the
# single source: hatch reads it at build, so importlib.metadata agrees with it, and the sibling
# drift guards (camada-backend, camada-web, camada-mkt) parse this file the way they parse a
# package.json. Plain X.Y.Z only (nothing PEP 440 adds), and @camada/python must stay in the
# analyst's SDK_NAMES: its sdkId drops anything else.
__version__ = "0.3.0"
SDK_ID = f"@camada/python/{__version__}"
