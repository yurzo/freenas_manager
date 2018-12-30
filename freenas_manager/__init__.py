import asyncio
import datetime as dt
import json
import logging

import pynetgear

logger = logging.getLogger(__name__)


class Host:

    @staticmethod
    def format_mac(mac):
        tokens = mac.split(':')
        int_tokens = [int(token, 16) for token in tokens]
        hexes = [f'{token:02x}' for token in int_tokens]
        return ':'.join(hexes)

    def __new__(cls, mac, **kwargs):

        mac = cls.format_mac(mac)

        if not hasattr(cls, '__instances__'):
            setattr(cls, '__instances__', {})

        if mac not in cls.__instances__:
            obj = super(Host, cls).__new__(cls)
            cls.__instances__[mac] = obj

        return cls.__instances__[mac]

    def __del__(self):
        logger.warning(f'deleting host: {self!r}')
        self.__instances__.pop(self.mac)

    def __init__(self, mac, ip=None, name=None, type=None):

        # reentry = False

        mac = self.format_mac(mac)

        if hasattr(self, 'mac'):
            assert self.mac == mac
            # before = self.__repr__()
            # reentry = True

        self.mac = mac

        if not hasattr(self, 'task'):
            self.task = None

        self.update_if_better('ip', ip)
        self.update_if_better('name', name)
        self.update_if_better('type', type)


        if not hasattr(self, 'wall_up'):
            loop = asyncio.get_event_loop()
            self.wall_up = dt.datetime.now()
            self.loop_up = loop.time()

        # after = self.__repr__()
        # if reentry and name is not None:
        #     logger.debug(f'before: {before}')
        #     logger.debug(f'after: {after}')

        if self.task is None:
            loop = asyncio.get_event_loop()
            self.task = loop.create_task(self.ping())
            # self.task.add_done_callback(self.del_task)
            logger.debug(f'Add ping task: {self.task}')

    def update_if_better(self, field, value):
        if not hasattr(self, field) or value is not None:
            setattr(self, field, value)


    def __repr__(self):
        tokens = [
            f'mac={self.mac}',
            f'ip={self.ip}',
            f'name={self.name}',
            f'uptime={self.uptime}',
            # f'done={self.task.done()}',
        ]
        sep = ', '
        return f'Host({sep.join(tokens)})'

    @property
    def uptime(self):
        loop = asyncio.get_event_loop()
        # return (loop.time - self.loop_up, dt.datetime.now() - self.wall_up)
        return loop.time() - self.loop_up

    async def ping(self):
        returncode = 0
        try:
            while returncode == 0:
                await asyncio.sleep(5)
                result = await run_subprocess(f'ping -c 5 -W 1000 {self.ip}')
                returncode = result[2]
        except asyncio.CancelledError:
            logger.debug('shutting down')
            raise
        finally:
            logger.debug('closed')

        logger.warning(f'{self!r} stopped pinging')

        del(self)

def get_passwords():
    with open('passwords.json', 'r') as hndl:
        return json.load(hndl)


def get_router_data():
    password = get_passwords()['router']['password']
    netgear = pynetgear.Netgear(password=password)
    return netgear.get_attached_devices()


async def run_subprocess(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    stdout, stderr = await proc.communicate()

    return stdout.decode(), stderr.decode(), proc.returncode
