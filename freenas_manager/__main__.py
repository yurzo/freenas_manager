import asyncio
import concurrent.futures
import functools
import os
import signal

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
            task.cancel()
            logger.debug(f"cancel {n}: {task!r}")


async def ip_monitor(queue):

    MAGIC_STRING = "Nmap scan report for"
    try:
        while True:
            logger.debug("calling nmap")
            stdout, stderr, _ = await run_subprocess("nmap -sP 192.168.1.0/24")
            for line in stdout.splitlines():
                if MAGIC_STRING in line:
                    ip = line.replace(MAGIC_STRING, "").strip()
                    logger.debug(f"active IPs: {ip}")
                    await queue.put(ip)
            logger.debug("sleeping")
            await asyncio.sleep(10)
    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def mac_resolver(ip_queue, mac_queue):
    try:
        while True:
            # logger.debug(f'items in queue: {queue.qsize()}')
            # await asyncio.sleep(5)
            logger.debug("calling arp")
            ip = await ip_queue.get()
            stdout, stderr, _ = await run_subprocess(f"arp {ip}")
            parsed = parse.parse("? ({ip}) at {mac} on en0 ifscope{}[ethernet]", stdout)

            if parsed is None:
                logger.debug("Woops")
                logger.debug(stdout)
                raise TypeError
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

            freenas_manager.Host(mac=ip_mac_map["mac"], ip=ip_mac_map["ip"])

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

                # logger.debug(f'{mac}')
                # logger.debug(f'{Host.__instances__.keys()}')

                if mac in Host.__instances__:
                    ip = Host.__instances__[mac].ip
                    freenas_manager.Host(
                        mac=mac, ip=ip, name=result.name, type=result.type
                    )

    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def manager():
    try:
        while True:
            await asyncio.sleep(10)
            macs = ["70:3e:ac:81:a7:b5", "04:69:f8:67:dc:90"]
            macs = [Host.format_mac(mac) for mac in macs]

    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


async def task_monitor(ip_queue, mac_queue):
    try:
        while True:
            loop = asyncio.get_event_loop()
            logger.info(f"time: {loop.time()}")
            tasks = asyncio.Task.all_tasks()

            total = len(tasks)
            cancelled = sum([task.cancelled() for task in tasks])
            done = sum([task.done() for task in tasks])

            logger.info(f"active tasks: {total - cancelled - done}")
            logger.info(f"cancelled tasks: {cancelled}")
            logger.info(f"done tasks: {done}")

            logger.info(f"ip queue depth: {ip_queue.qsize()}")
            logger.info(f"mac queue depth: {mac_queue.qsize()}")
            if hasattr(Host, "__instances__"):
                logger.info(f"hosts: {len(Host.__instances__)}")

                for host in Host.__instances__.values():
                    logger.info(f"{host!r}")

            await asyncio.sleep(5)
    except asyncio.CancelledError:
        logger.debug("shutting down")
        raise
    finally:
        logger.debug("closed")


# def configure_logging():
#
#     formatter = logging.Formatter(
#         "%(asctime)s %(levelname)s (%(name)s.%(funcName)s): %(message)s"
#     )
#
#     stream_handler = logging.StreamHandler()
#     stream_handler.setFormatter(formatter)
#     stream_handler.setLevel(logging.WARNING)
#
#     file_handler = logging.FileHandler("output.log")
#     file_handler.setFormatter(formatter)
#     file_handler.setLevel(logging.DEBUG)
#
#     logger = logging.getLogger(__name__)
#     logger.root.setLevel(logging.DEBUG)
#     logger.root.addHandler(stream_handler)
#     logger.root.addHandler(file_handler)
#
#     file_handler = logging.FileHandler("output_info.log")
#     file_handler.setFormatter(formatter)
#     file_handler.setLevel(logging.INFO)
#     logger.root.addHandler(file_handler)


def main():
    # logging.basicConfig(filename='example.log',level=logging.DEBUG)
    # configure_logging()

    loop = asyncio.get_event_loop()

    ip_queue = asyncio.Queue()
    mac_queue = asyncio.Queue()

    tasks = asyncio.gather(
        ip_monitor(ip_queue),
        mac_resolver(ip_queue, mac_queue),
        assemble_hosts(mac_queue),
        name_resolver(),
        task_monitor(ip_queue, mac_queue),
        manager(),
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
    main()
