import asyncio
import datetime as dt
import json

from loguru import logger

import pynetgear


class Host:

    __instances__ = None

    @staticmethod
    def format_mac(mac):
        try:
            tokens = mac.split(":")
            int_tokens = [int(token, 16) for token in tokens]
            hexes = [f"{token:02x}" for token in int_tokens]
            return ":".join(hexes)
        except ValueError:
            return None

    @classmethod
    def get_instances(cls):
        if cls.__instances__:
            return cls.__instances__
        else:
            return {}

    def __new__(cls, mac, **kwargs):

        mac = cls.format_mac(mac)

        assert mac is not None

        if cls.__instances__ is None:
            cls.__instances__ = {}

        if mac not in cls.__instances__:
            logger.debug(f"New mac: {mac}, creating host")
            obj = super(Host, cls).__new__(cls)
            cls.__instances__[mac] = obj
        else:
            logger.debug(f"Existing mac: {mac}")

        return cls.__instances__[mac]

    def destroy(self):
        logger.warning(f"deleting host: {self!r}")
        self.__instances__.pop(self.mac)
        logger.warning(f"host deleted")

    def __init__(self, mac, ip=None, name=None, type=None):

        mac = self.format_mac(mac)

        if hasattr(self, "mac"):
            assert self.mac == mac

        self.mac = mac

        if not hasattr(self, "task"):
            self.task = None

        self._updated = False

        self.update_if_better("ip", ip)
        self.update_if_better("name", name)
        self.update_if_better("type", type)

        if not hasattr(self, "wall_up"):
            loop = asyncio.get_event_loop()
            self.wall_up = dt.datetime.now()
            self.loop_up = loop.time()
            logger.debug(f"{self.mac}.uptime:{self.wall_up}")

        if self.task is None:
            loop = asyncio.get_event_loop()
            logger.debug(f"adding heartbeat task...")
            self.task = loop.create_task(self.heart_beat())

    def update_if_better(self, field, value):
        if not hasattr(self, field):
            setattr(self, field, value)
        elif value is not None:
            current = getattr(self, field)
            if current != value:
                self._updated = True
            setattr(self, field, value)

    @property
    def updated(self):
        result = self._updated
        self._updated = False
        return result

    def __repr__(self):
        tokens = [
            f"mac={self.mac}",
            f"ip={self.ip}",
            f"name={self.name}",
            f"uptime={self.uptime}",
        ]
        sep = ", "
        return f"Host({sep.join(tokens)})"

    @property
    def uptime(self):
        loop = asyncio.get_event_loop()
        return loop.time() - self.loop_up

    @staticmethod
    async def ping(ip):
        logger.debug(f"starting ping {ip}")
        result = await run_subprocess(f"ping -c 5 {ip}")
        returncode = result[2]
        logger.debug(f"pinged {ip}, returncode={returncode}")
        return returncode == 0

    async def heart_beat(self):
        returncode = 0
        try:
            for retry in range(4):
                while await self.ping(self.ip):
                    await asyncio.sleep(15)
                logger.debug(f"ping {self.ip} failed - try {retry + 1}/4")

        except asyncio.CancelledError:
            logger.debug("shutting down")
            raise
        finally:
            logger.debug("closed")

        logger.warning(f"{self!r} stopped pinging")
        self.destroy()


def get_passwords():
    with open("passwords.json", "r") as hndl:
        return json.load(hndl)


def get_router_data():
    password = get_passwords()["router"]["password"]
    netgear = pynetgear.Netgear(password=password)
    return netgear.get_attached_devices()


async def run_subprocess(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return stdout.decode(), stderr.decode(), proc.returncode
    except asyncio.TimeoutError:
        logger.warning(f"'{cmd}' timed out")
        return "", "", 1
