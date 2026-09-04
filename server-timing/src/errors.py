"""Exception types for srvtime.

A failed measurement does not raise: ``probe.probe`` catches network errors and
returns a :class:`~srvtime.probe.Result` with ``error`` set, so a single failed
request never breaks the series. These exceptions are used only
for configuration/argument problems that should abort the whole run.
"""


class SrvtimeError(Exception):
    """Base class for srvtime errors."""


class InvalidURL(SrvtimeError):
    """The URL is missing a scheme or host."""


class AllRequestsFailed(SrvtimeError):
    """The first 3 requests of a series all failed — abort early."""


class ThresholdExceeded(SrvtimeError):
    """p95 crossed the ``--threshold-p95`` limit (CI/cron gate)."""


def short_error(exc: BaseException) -> str:
    """Render an exception as a short ``TypeName: message`` string.

    Network libraries attach long chain messages; we keep the type and the
    first argument, capped so the table cell stays readable.
    """
    msg = ""
    if exc.args:
        msg = str(exc.args[0])
    name = type(exc).__name__
    text = f"{name}: {msg}" if msg else name
    return text[:200]
