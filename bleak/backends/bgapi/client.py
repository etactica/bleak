import uuid

import asyncio
import logging
import struct
import sys
import threading
from typing import Callable, Dict, Optional, Union, cast
from uuid import UUID
import warnings

import bgapi

if sys.version_info[:2] < (3, 8):
    from typing_extensions import Literal, TypedDict
else:
    from typing import Literal, TypedDict

from ..characteristic import BleakGATTCharacteristic
from ..client import BaseBleakClient, NotifyCallback
from ..device import BLEDevice
from ..service import BleakGATTServiceCollection

from .characteristic import BleakGATTCharacteristicBGAPI
#from .descriptor import BleakGATTDescriptorP4Android
from .service import BleakGATTServiceBGAPI


logger = logging.getLogger(__name__)

class BleakClientBGAPI(BaseBleakClient):
    """
    A client built to talk to a Silabs "BGAPI"
    NCP device.
    """

    def __init__(self, address_or_ble_device: Union[BLEDevice, str], **kwargs):
        super(BleakClientBGAPI, self).__init__(address_or_ble_device, **kwargs)

        self._device = None
        if isinstance(address_or_ble_device, BLEDevice):
            self._device = address_or_ble_device

        self._loop = asyncio.get_running_loop()
        self._ch: Optional[int] = None
        # used to override mtu_size property
        self._mtu_size: Optional[int] = None

        self._adapter: Optional[str] = kwargs.get("adapter", kwargs.get("ncp"))
        self._bgapi = kwargs.get("bgapi", "/home/karlp/SimplicityStudio/SDKs/gecko_sdk_2/protocol/bluetooth/api/sl_bt.xapi")
        ### XXX are we in trouble here making a new serial connection? the scanner does too!
        self._lib = bgapi.BGLib(bgapi.SerialConnector(self._adapter), self._bgapi, event_handler=self._bgapi_evt_handler)
        self._ev_connect = asyncio.Event()
        self._ev_gatt_op = asyncio.Event()

    async def connect(self, **kwargs) -> bool:
        self._lib.open()  # this starts a new thread, remember that!
        # XXX make this more reliable? if it fails hello, try again, try reset?
        self._lib.bt.system.hello()
        # Can't / shouldn't do a reset here?!  I wish the serial layer was more robust! (are we just not cleaning up after ourselves well enough?

        # TODO - move this elsewhere? we like it now for tracking adapters, but bleak has no real concept of that.
        _, self._our_address, self._our_address_type = self._lib.bt.system.get_identity_address()
        logger.info("Our Bluetooth %s address: %s", "static random" if self._our_address_type else "public device", self._our_address)

        phy = self._lib.bt.gap.PHY_PHY_1M  # XXX: some people _may_ wish to specify this. (can't us PHY_ANY!)
        atype = self._lib.bt.gap.ADDRESS_TYPE_PUBLIC_ADDRESS
        if self._device:
            # FIXME - we have the address type information in the scanner, make sure it gets here?
            pass
        _, self._ch = self._lib.bt.connection.open(self.address, atype, phy)

        async def waiter():
            await self._ev_connect.wait()

        try:
            await asyncio.wait_for(waiter(), timeout=self._timeout)
        except asyncio.exceptions.TimeoutError:
            logger.warning("um, the other async timeout erorr?")
        except TimeoutError:
            logger.warning('KKK timeout waiting for connection!')

        if self._ch:
            print("we got connected, let's do shit then!")
        else:
            raise asyncio.TimeoutError

        # nominally, you don't need to do this, but it's how bleak behaves, so just do it, even though it's "wasteful" to enumerate everything
        await self.get_services()

        return True

    async def disconnect(self) -> bool:
        logger.debug("attempting to disconnect")
        if self._ch:
            self._lib.bt.connection.close(self._ch)
        self._ch = None
        return True

    def _bgapi_evt_handler(self, evt):
        """
        THIS RUNS IN THE BGLIB THREAD!
        and because of this, we can't call commands from here ourself, we'd have to
        recall them back onto the other thread?
        """
        #print(f"received bgapi evt:  {evt}")
        if evt == "bt_evt_system_boot":
            # This handles starting scanning if we were reset...
            logger.debug("NCP booted: %d.%d.%db%d hw:%d hash: %x", evt.major, evt.minor, evt.patch, evt.build, evt.hw, evt.hash)
            # We probably don't want to do anything else here?!
        elif evt == "bt_evt_connection_opened":
            # Right? right?!
            assert(self._ch == evt.connection)
            # do this on the right thread!
            self._loop.call_soon_threadsafe(self._ev_connect.set)
            logger.warning("flagged as connected!")
        elif evt == "bt_evt_connection_closed":
            logger.info("Disconnected connection: %d: reason: %d (%#x)", evt.connection, evt.reason, evt.reason)
        elif (evt == "bt_evt_connection_parameters"
                or evt == "bt_evt_connection_phy_status"
                or evt == "bt_evt_connection_remote_used_features"
                ):
            logger.debug("ignornig 'extra' info in: %s", evt)
            # We don't need anything else here? just confirmations, and avoid "unhandled" warnings?
        elif evt == "bt_evt_gatt_mtu_exchanged":
            self._mtu_size = evt.mtu

        elif evt == "bt_evt_gatt_service":
            uus = None
            if len(evt.uuid) == 2:
                uu, = struct.unpack("<H", evt.uuid)
                uus = f"0000{uu:04x}-0000-1000-8000-00805f9b34fb"
            elif len(evt.uuid) == 4:
                uu, = struct.unpack("<L", evt.uuid)
                uus = f"{uu:08x}-0000-1000-8000-00805f9b34fb"
            elif len(evt.uuid) == 16:
                uus = f"{uuid.UUID(bytes=bytes(reversed(evt.uuid)))}"
            else:
                # let's see, will BGAPI give us zero here sometimes? *fingers crossed*
                raise RuntimeError("Illegal uuid data size?!")

            service = BleakGATTServiceBGAPI(dict(uuid=uus, handle=evt.service))
            self._loop.call_soon_threadsafe(self.services.add_service, service)

        elif evt == "bt_evt_gatt_characteristic":
            uus = None
            if len(evt.uuid) == 2:
                uu, = struct.unpack("<H", evt.uuid)
                uus = f"0000{uu:04x}-0000-1000-8000-00805f9b34fb"
            elif len(evt.uuid) == 4:
                uu, = struct.unpack("<L", evt.uuid)
                uus = f"{uu:08x}-0000-1000-8000-00805f9b34fb"
            elif len(evt.uuid) == 16:
                uus = f"{uuid.UUID(bytes=bytes(reversed(evt.uuid)))}"
            else:
                # let's see, will BGAPI give us zero here sometimes? *fingers crossed*
                raise RuntimeError("Illegal uuid data size?!")

            # um, we don't have these here, need to post back elsewhere?
            #char = BleakGATTCharacteristicBGAPI(dict(uuid=uus, handle=evt.service), suuid, sh, max_write)
            print("saw char: ", uus)
            #self._loop.call_soon_threadsafe(self.services.add_service, service)
        elif evt == "bt_evt_gatt_procedure_completed":
            self._loop.call_soon_threadsafe(self._ev_gatt_op.set)
        else:
            logger.warning(f"unhandled bgapi evt! {evt}")

    @property
    @property
    def mtu_size(self) -> int:
        """Get ATT MTU size for active connection"""
        if self._mtu_size is None:
            warnings.warn(
                "Using default MTU value. Call _acquire_mtu() or set _mtu_size first to avoid this warning."
            )
            return 23

        return self._mtu_size

    async def pair(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def unpair(self) -> bool:
        raise NotImplementedError

    @property
    def is_connected(self) -> bool:
        return self._ch

    async def get_services(self, **kwargs) -> BleakGATTServiceCollection:
        if self._services_resolved:
            return self.services
        logger.debug("Attempting to recursively load services")

        # same again, fire the event, wait for shit
        self._ev_gatt_op.clear()

        self._lib.bt.gatt.discover_primary_services(self._ch)
        await self._ev_gatt_op.wait()

        # We don't do nested things, we get all the services, then get the characteristics.
        for s in self.services:
            self._ev_gatt_op.clear()
            self._lib.bt.gatt.discover_characteristics(self._ch, s.handle)
            await self._ev_gatt_op.wait()
            # TODO - and again for descriptors I guess?

        self._services_resolved = True
        return self.services

    async def read_gatt_char(self, char_specifier: Union[BleakGATTCharacteristic, int, str, uuid.UUID],
                             **kwargs) -> bytearray:
        raise NotImplementedError

    async def read_gatt_descriptor(self, handle: int, **kwargs) -> bytearray:
        raise NotImplementedError

    async def write_gatt_char(self, char_specifier: Union[BleakGATTCharacteristic, int, str, uuid.UUID],
                              data: Union[bytes, bytearray, memoryview], response: bool = False) -> None:
        raise NotImplementedError

    async def write_gatt_descriptor(self, handle: int, data: Union[bytes, bytearray, memoryview]) -> None:
        raise NotImplementedError

    async def start_notify(self, characteristic: BleakGATTCharacteristic, callback: NotifyCallback, **kwargs) -> None:
        raise NotImplementedError

    async def stop_notify(self, char_specifier: Union[BleakGATTCharacteristic, int, str, uuid.UUID]) -> None:
        raise NotImplementedError



