import asyncio
import logging
import struct
import sys
from typing import Callable, Coroutine, Dict, List, Optional
from warnings import warn

import bgapi

if sys.version_info[:2] < (3, 8):
    from typing_extensions import Literal, TypedDict
else:
    from typing import Literal, TypedDict

from ...exc import BleakError
from ..scanner import AdvertisementData, AdvertisementDataCallback, BaseBleakScanner

logger = logging.getLogger(__name__)

class BleakScannerBGAPI(BaseBleakScanner):
    """
    A scanner built to talk to a Silabs "BGAPI"
    NCP device.
    """

    def __init__(
            self,
            detection_callback: Optional[AdvertisementDataCallback],
            service_uuids: Optional[List[str]],
            scanning_mode: Literal["active", "passive"],
            **kwargs,
    ):

        super(BleakScannerBGAPI, self).__init__(detection_callback, service_uuids)
        self._adapter: Optional[str] = kwargs.get("adapter", kwargs.get("ncp"))

        self._bgapi = kwargs.get("bgapi", "/home/karlp/SimplicityStudio/SDKs/gecko_sdk_2/protocol/bluetooth/api/sl_bt.xapi")

        self._loop = asyncio.get_running_loop()
        self._lib = bgapi.BGLib(bgapi.SerialConnector(self._adapter), self._bgapi, event_handler=self._bgapi_evt_handler)

        scan_modes = {
            "passive": self._lib.bt.scanner.SCAN_MODE_SCAN_MODE_PASSIVE,
            "active": self._lib.bt.scanner.SCAN_MODE_SCAN_MODE_ACTIVE,
        }
        # TODO - might make this a "backend option"?
        self._phy = self._lib.bt.scanner.SCAN_PHY_SCAN_PHY_1M_AND_CODED
        # TODO - might make this a "backend option"?
        # Discover mode seems to be an internal filter on what it sees?
        # maybe use the "filters" blob for this?
        # I definitely need OBSERVATION for my own stuff at least.
        #self._discover_mode = self._lib.bt.scanner.DISCOVER_MODE_DISCOVER_GENERIC
        self._discover_mode = self._lib.bt.scanner.DISCOVER_MODE_DISCOVER_OBSERVATION
        self._scanning_mode = scan_modes.get(scanning_mode, scan_modes["passive"])
        if scanning_mode == "passive" and service_uuids:
            logger.warning(
                "service uuid filtering with passive scanning is super unreliable..."
            )

        # Don't bother supporting the deprecated set_scanning_filter in new work.
        self._scanning_filters = {}
        filters = kwargs.get("filters")
        if "filters":
            self._scanning_filters = filters

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
            self._loop.call_soon_threadsafe(self._lib.bt.scanner.set_mode, self._phy, self._scanning_mode)
            self._loop.call_soon_threadsafe(self._lib.bt.scanner.start, self._phy, self._discover_mode)
        elif evt == "bt_evt_scanner_legacy_advertisement_report":
            rssif = self._scanning_filters.get("rssi",  -255)
            if evt.rssi > rssif:
                self._loop.call_soon_threadsafe(self._handle_advertising_data, evt, evt.data)

    async def start(self):
        self._lib.open()  # this starts a new thread, remember that!
        # XXX make this more reliable? if it fails hello, try again, try reset?
        self._lib.bt.system.hello()
        # Get Bluetooth address
        _, self.address, self.address_type = self._lib.bt.system.get_identity_address()
        logger.info("Our Bluetooth %s address: %s",
                      "static random" if self.address_type else "public device",
                      self.address)

        # Calling reset gets us into a known state, and we're being asked to
        # start scanning anyway.  We may want to change this if you want to
        # turn scanning on / off while staying connected to other devices?
        # but that will require quite a bit more state detection?
        self._lib.bt.system.reset(0)
        # Alternately, just explicitly try and call start ourselves...
        # Chances of the bluetooth stack not being booted are ... 0?
        #self._lib.bt.scanner.set_mode(self._phy, self._scanning_mode)
        #self._lib.bt.scanner.start(self.phy, self._scanning_mode)


    async def stop(self):
        logger.debug("Stopping scanner")
        self._lib.bt.scanner.stop()
        self._lib.close()


    def set_scanning_filter(self, **kwargs):
        # BGAPI doesn't do any itself, but doing it bleak can still be very userfriendly.
        self._scanning_filters = kwargs
        #raise NotImplementedError("BGAPI doesn't provide NCP level filters")

    def _handle_advertising_data(self, evt, raw):
        """
        Make a bleak AdvertisementData() from our raw data, we'll fill in what we can.
        :param data:
        :return:
        """
        # There's more stuff in the evt, like flags, channel, address type,
        # target address?  at least the flags are interesting?

        items = {}
        #if len(raw) == 0:
        #    # FIXME - No, need to callback with an empty AD, but real Device?
        #    return
        index = 0
        # This feels gross, I know I've done this neater before...
        while index < len(raw):
            remaining = raw[index:]
            #print(f"remaining now = {[hex(a) for a in remaining]}")
            flen = remaining[0]
            index = index + flen + 1  # account for length byte too!
            if flen == 0:
                continue
            chunk = remaining[1:1+flen]
            type = chunk[0]
            dat = chunk[1:]
            items[type] = (type, dat)

        local_name = None
        service_uuids = []
        manufacturer_data = {}
        tx_power = None
        service_data = {}

        for type, dat in items.values():
            # Ok, do a little extra magic?
            # Assigned numbers sec 2.3
            if type in [0x2, 0x3]:
                # meh, at least attempt to get 16bit service ids...
                num = len(dat) // 2
                uuids16 = [struct.unpack_from("<h", dat, a*2)[0] for a in range(num)]
                service_uuids.extend(uuids16)
            if type in [4,5,6,7]:
                # FIXME handle 32 and 128bit explicit services?
                pass
            if type in [0x08, 0x09]:
                # FIXME - um, shortened name? do we just call that local name?
                # XXX - sometimes we get trailing zero bytes here? just remove them.
                local_name = dat.decode("utf8").rstrip('\0')
            if type == 0x0a:
                tx_power, = struct.unpack_from("<b", dat, 0)
            if type == 0x16:
                # FIXME - service data.
                pass
            if type == 0xff:
                vendor, = struct.unpack("<h", dat[0:2])
                manufacturer_data[vendor] = dat[2:]

        advertisement_data = AdvertisementData(
            local_name=local_name,
            manufacturer_data=manufacturer_data,
            service_data=None, # FIXME
            service_uuids=service_uuids,
            tx_power=tx_power,
            rssi=evt.rssi,
            platform_data=None
       )
        # Pretty sure "None" for the platform handle for this device isn't helpful?
        devname = local_name if local_name else evt.address.replace(":", "-").upper()
        device = self.create_or_update_device(evt.address, devname, evt.address, advertisement_data)
        if self._callback is None:
            return

        self._callback(device, advertisement_data)


