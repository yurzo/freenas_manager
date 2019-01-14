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

        self.update_if_better("_ip", ip)
        self.update_if_better("_name", name)
        self.update_if_better("_type", type)

        self._updated = False

        # if not hasattr(self, "task"):
        #     self.task = None

        # self._updated = False

        loop = asyncio.get_event_loop()

        if not hasattr(self, "wall_up"):
            self.wall_up = dt.datetime.now()
            self.loop_up = loop.time()
            logger.debug(f"{self.mac}.uptime:{self.wall_up}")

        if not hasattr(self, 'task'):
            logger.debug(f"adding heartbeat task...")
            self.task = loop.create_task(self.heart_beat())

        self.last_refresh = loop.time()

    def update_if_better(self, field, value):
        if not hasattr(self, field) or value is not None:
            setattr(self, field, value)

    def set_and_flag(self, field, value):
        current = getattr(self, field)
        if current != value and value is not None:
            setattr(self, field, value)
            self._updated = True

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, _ip):
        self.set_and_flag("_ip", _ip)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, _name):
        self.set_and_flag("_name", _name)

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, _type):
        self.set_and_flag("_type", _type)

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
            f"uptime={self.uptime:2.2f}",
            f"type={self.type}",
            f"dwell={self.dwell:2.2f}",
        ]
        sep = ", "
        return f"Host({sep.join(tokens)})"

    @property
    def uptime(self):
        loop = asyncio.get_event_loop()
        return loop.time() - self.loop_up

    @property
    def dwell(self):
        loop = asyncio.get_event_loop()
        return loop.time() - self.last_refresh

    # @staticmethod
    # async def ping(ip):
    #     logger.debug(f"starting ping {ip}")
    #     result = await run_subprocess(f"ping -c 5 {ip}")
    #     returncode = result[2]
    #     logger.debug(f"pinged {ip}, returncode={returncode}")
    #     return returncode == 0

    async def heart_beat(self):
        try:
            while self.dwell < 120:
                await asyncio.sleep(15)
            logger.debug(f"{self.dwell} since last seen")
        except asyncio.CancelledError:
            logger.debug("shutting down")
            raise
        finally:
            logger.debug("closed")
        logger.warning(f"{self!r} stopped refreshing")
        self.destroy()

    # async def heart_beat(self):
    #     returncode = 0
    #     try:
    #         for retry in range(4):
    #             while await self.ping(self.ip):
    #                 await asyncio.sleep(15)
    #             logger.debug(f"ping {self.ip} failed - try {retry + 1}/4")
    #
    #     except asyncio.CancelledError:
    #         logger.debug("shutting down")
    #         raise
    #     finally:
    #         logger.debug("closed")
    #
    #     logger.warning(f"{self!r} stopped pinging")
    #     self.destroy()


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
