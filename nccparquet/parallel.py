"""Parse archive members on several processes at once.

Each worker handles one file. The parent applies the duplicate check and
writes rows, so two files that contain the same line still store it once.
"""

import multiprocessing as mp
import os
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait


def job_count(requested):
    if requested and requested > 0:
        return requested
    return os.cpu_count() or 1


def map_unordered(jobs, items, function, on_result):
    """Call function(*item) for each item. items may be a generator."""
    jobs = max(1, jobs)
    iterator = iter(items)
    first = next(iterator, None)
    if first is None:
        return
    if jobs == 1:
        on_result(function(*first))
        for item in iterator:
            on_result(function(*item))
        return

    context = mp.get_context("spawn")
    pending = set()
    with ProcessPoolExecutor(max_workers=jobs, mp_context=context) as pool:
        def submit(item):
            pending.add(pool.submit(function, *item))

        def drain(limit):
            nonlocal pending
            while len(pending) > limit:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    on_result(future.result())

        submit(first)
        for item in iterator:
            drain(jobs)
            submit(item)
        drain(0)
