import asyncio
import concurrent.futures
import functools
import os
import platform
import signal
import sys

import freenas_manager
from freenas_manager import Host, run_subprocess

from loguru import logger

import parse


def cancel_tasks(signame, gathered_tasks=None):
    print("got signal %s: exit" % signame)

    if gathered_tasks is not None:
        logger.debug(f"global cancelation via: {gathered_tasks}")
        gathered_tasks.cancel()

    tasks = asyncio.Task.all_tasks()

    cancelled = [task.cancelled() for task in tasks]
    logger.debug(f"tasks cancelled: {sum(cancelled)} out of {len(cancelled)}")

    if not all(cancelled):
        logger.debug(f"fallback to cancellation by task")
        for n, task in enumerate(tasks):
            if task.done():
                continue
            if not task.cancelled():
                task.cancel()
                logger.debug(f"cancel {n}: {task!r}")


async def ip_monitor(ip_queue):
    MAGIC_STRING = "Nmap scan report for"
    try:
        while True:
            stdout, stderr, _ = await run_subprocess("nmap -sP 192.168.1.0/24")
            for line in stdout.splitlines():
                if MAGIC_STRING in line:
                    ip = line.replace(MAGIC_STRING, "").strip()
                    logger.debug(f"nmap active ip: {ip}")
                    await ip_queue.put(ip)
                    await asyncio.sleep(1)
            await asyncio.sleep(30)
    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def mac_resolver(ip_queue, mac_queue):
    try:
        while True:

            ip = await ip_queue.get()
            opt = "" if platform.system() == "Darwin" else "-a"
            cmd = " ".join(["arp", opt, ip])
            stdout, stderr, returncode = await run_subprocess(cmd)

            parsed = parse.parse("? ({ip}) at {mac} {reminder}", stdout)

            if returncode != 0:
                logger.warning(f"bad arp result for {ip}")
                logger.debug(f"command was: {cmd}")
                logger.debug(stdout, stderr, parsed)
                continue

            if "entries no match found" in stdout:
                logger.debug(f"bad arp result for {ip}")
                logger.debug(f"command was: {cmd}")
                logger.debug(stdout, stderr, parsed)
                continue

            if parsed is None:
                logger.debug("Arp completed but we don't understand the answer")
                logger.debug(stdout, stderr, parsed)
                raise TypeError

            mac = Host.format_mac(parsed["mac"])
            ip = parsed["ip"]

            if mac is not None:
                await mac_queue.put(parsed.named)

    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def assemble_hosts(mac_queue):
    try:
        while True:
            ip_mac_map = await mac_queue.get()
            mac = Host.format_mac(ip_mac_map["mac"])
            ip = ip_mac_map["ip"]
            Host(mac=mac, ip=ip)

    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def name_resolver():
    try:
        while True:
            await asyncio.sleep(30)
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                results = await loop.run_in_executor(
                    pool, freenas_manager.get_router_data
                )
            for result in results:
                mac = Host.format_mac(result.mac)

                if mac is None:
                    continue

                instances = Host.get_instances()

                # get_router_data might return stale values
                # so onlu update hosts that already Existing

                if mac in instances:
                    host = instances[mac]
                    host.name = result.name
                    host.type = result.type

    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def task_monitor(ip_queue, mac_queue):
    previous_macs = set()
    loop = asyncio.get_event_loop()
    try:
        while True:

            tasks = asyncio.Task.all_tasks()

            total = len(tasks)
            cancelled = sum([task.cancelled() for task in tasks])
            done = sum([task.done() for task in tasks])
            active = total - cancelled - done

            instances = Host.get_instances()

            monitor = " ".join(
                [
                    f"active: {active}",
                    f"cancelled: {cancelled}",
                    f"done: {done}",
                    f"ip_queue: {ip_queue.qsize()}",
                    f"mac_queue: {mac_queue.qsize()}",
                    f"hosts: {len(instances)}",
                ]
            )

            logger.debug(monitor)

            if instances:

                current_macs = set(instances.keys())

                lost_macs = previous_macs - current_macs
                new_macs = current_macs - previous_macs

                for mac in lost_macs:
                    logger.info(f"departed: {mac}")

                for mac in new_macs:
                    host = instances[mac]
                    logger.info(f"arrived: {host!r}")

                for host in instances.values():
                    if host.updated:
                        logger.info(f"updated: {host!r}")

                if lost_macs or new_macs:
                    logger.info(monitor)

                previous_macs = current_macs

            await asyncio.sleep(5)
    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


def main():

    loop = asyncio.get_event_loop()

    ip_queue = asyncio.Queue()
    mac_queue = asyncio.Queue()

    tasks = asyncio.gather(
        ip_monitor(ip_queue),
        mac_resolver(ip_queue, mac_queue),
        assemble_hosts(mac_queue),
        name_resolver(),
        task_monitor(ip_queue, mac_queue),
    )

    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    for signame in ("SIGINT", "SIGTERM"):
        loop.add_signal_handler(
            getattr(signal, signame), functools.partial(cancel_tasks, signame, tasks)
        )

    print("Event loop running forever, press Ctrl+C to interrupt.")
    print("pid %s: send SIGINT or SIGTERM to exit." % os.getpid())
    try:
        loop.run_until_complete(tasks)
    except asyncio.CancelledError:
        loop.stop()
    finally:
        loop.close()


if __name__ == "__main__":

    logger.remove(0)  # remove default logger
    DEBUG = True
    if DEBUG:
        logger.add(sys.stderr, level="INFO")
    logger.add(
        "output.log",
        level="DEBUG",
        rotation="1 day",
        retention="10 days",
        compression="zip",
    )

    main()
