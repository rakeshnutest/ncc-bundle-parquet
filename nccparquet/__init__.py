"""Read a packed NCC tar.gz into Panacea-shaped Parquet."""

__all__ = ["run_logs", "run_sar"]


def run_logs(*args, **kwargs):
    from nccparquet.logs import run_logs as _run

    return _run(*args, **kwargs)


def run_sar(*args, **kwargs):
    from nccparquet.sar import run as _run

    return _run(*args, **kwargs)
