import asyncio
import gc
import logging
import os
import selectors
import sys
import time

import ofrak_angr
from ofrak import OFRAK, OFRAKContext  # type:ignore
from ofrak.core import Elf


# Borrowed from https://gist.github.com/vxgmichel/620eb3a02d97d3da9dacdc508a5d5321
class TimedSelector(selectors.DefaultSelector):
    select_time = 0

    def reset_select_time(self):
        self.select_time = 0

    def select(self, timeout=None):
        if timeout is not None and timeout <= 0:
            return super().select(timeout)
        start = time.perf_counter_ns()
        try:
            return super().select(timeout)
        finally:
            self.select_time += time.perf_counter_ns() - start


class TimedEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    def new_event_loop(self):
        selector = TimedSelector()
        return asyncio.DefaultEventLoopPolicy._loop_factory(selector)


def mystrtime(ns: int) -> str:
    if ns > 1_000_000_000:
        return f"{ns/1_000_000_000:.2f}s"
    else:
        return f"{ns/1_000_000:.1f}ms"


async def unpack_one(ofrak_context: OFRAKContext, path: str) -> None:
    root = await ofrak_context.create_root_resource_from_file(path)
    await root.unpack_recursively(do_not_unpack=[Elf])
    await root.auto_run_recursively(all_identifiers=True)


async def main() -> None:
    o = OFRAK(logging_level=logging.WARN)
    o.discover(ofrak_angr)
    # gc.set_debug(gc.DEBUG_STATS)
    # print("Original GC thresholds: ", gc.get_threshold(), file=sys.stderr)
    t0, t1, t2 = gc.get_threshold()  # AN: returns 700, 10, 10 in my environment
    gc.set_threshold(max(t0, 10240), max(24, t1), max(25, t2))
    # print("Updated GC thresholds: ", gc.get_threshold(), file=sys.stderr)
    ofrak_context = await o.create_ofrak_context()
    start_perf = time.perf_counter_ns()
    start_process = time.process_time_ns()
    asyncio.get_event_loop()._selector.reset_select_time()
    await unpack_one(ofrak_context, sys.argv[2])
    s1 = gc.get_stats()
    mid_perf = time.perf_counter_ns()
    mid_process = time.process_time_ns()
    mid_select_time = asyncio.get_event_loop()._selector.select_time
    await unpack_one(ofrak_context, sys.argv[3])
    s2 = gc.get_stats()
    end_perf = time.perf_counter_ns()
    end_process = time.process_time_ns()
    end_select_time = asyncio.get_event_loop()._selector.select_time
    p1_blocked_time = max(0, mid_perf - start_perf - mid_process + start_process - mid_select_time)
    ofrak_context.job_service.print_stats()
    print(
        (
            f"Time in {sys.argv[1]} unpack {os.path.basename(sys.argv[2])}: {mystrtime(mid_perf-start_perf)} wall,"
            f" {mystrtime(mid_process-start_process)} CPU, {mystrtime(mid_select_time)} async select,"
            f" {mystrtime(p1_blocked_time)} blocked, GC stats: {s1}"
        ),
        file=sys.stderr,
    )
    p2_blocked_time = max(
        0, end_perf - mid_perf - end_process + mid_process - end_select_time + mid_select_time
    )
    print(
        (
            f"Time in {sys.argv[1]} unpack {os.path.basename(sys.argv[3])}: {mystrtime(end_perf-mid_perf)} wall,"
            f" {mystrtime(end_process-mid_process)} CPU, {mystrtime(end_select_time-mid_select_time)} async select,"
            f" {mystrtime(p2_blocked_time)} blocked"
        ),
        file=sys.stderr,
    )
    blocked_time = max(0, end_perf - start_perf - end_process + start_process - end_select_time)
    print(
        (
            f"Time in {sys.argv[1]} unpack x2: {mystrtime(end_perf-start_perf)} wall,"
            f" {mystrtime(end_process-start_process)} CPU, {mystrtime(end_select_time)} async select,"
            f" {mystrtime(blocked_time)} blocked, GC stats: {s2}"
        ),
        file=sys.stderr,
    )


asyncio.set_event_loop_policy(TimedEventLoopPolicy())
asyncio.get_event_loop().run_until_complete(main())
