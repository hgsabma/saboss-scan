"""Saboss Platform: shared foundation for Saboss Technologies products.

The platform owns everything that is not specific to one product:
accounts, organizations and roles, sessions, API keys, audit logging,
notifications, configuration and the web shell (layout, design system).

Products live in sub-packages (Saboss Scan is ``saboss_platform.scan``) and
plug in by providing their own database models and routers. See
docs/ARCHITECTURE.md.
"""

__version__ = "0.4.0"
