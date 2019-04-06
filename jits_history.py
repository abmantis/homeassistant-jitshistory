"""
A component which allows you to send data to JSON IoT Server.
"""
import aiohttp
import logging
from datetime import timedelta

from Crypto.Cipher import AES
import base64
import binascii
import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.const import (
    CONF_WHITELIST, CONF_URL, STATE_UNKNOWN, STATE_UNAVAILABLE,
    CONF_SCAN_INTERVAL)
from homeassistant.helpers import state as state_helper
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import track_point_in_time
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'jits_history'
CONF_CLIENTS = 'clients'
CONF_CONNECTION_KEY = 'connection_key'
CONF_AES_KEY = 'aes_key'

CLIENT_SCHEMA = vol.Schema({
    vol.Required(CONF_CONNECTION_KEY): cv.string,
    vol.Required(CONF_AES_KEY): cv.string,
    vol.Required(CONF_WHITELIST): vol.Schema({cv.entity_id: cv.string}),
})

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_URL): cv.string,
        vol.Optional(CONF_SCAN_INTERVAL, default=30): cv.positive_int,
        vol.Required(CONF_CLIENTS): vol.Schema([CLIENT_SCHEMA]),
    }),
}, extra=vol.ALLOW_EXTRA)


@asyncio.coroutine
def async_setup(hass, config):
    """Set up the JITS history component."""
    conf = config[DOMAIN]

    def get_aes_iv(url, connection_key):
        generator_url = "{}/generatorIV.php".format(url)
        parameters = {'con': connection_key}

        try:
            session = async_get_clientsession(hass)
            with async_timeout.timeout(DEFAULT_TIMEOUT, loop=hass.loop):
                req = yield from session.post(generator_url, data=parameters,
                                              timeout=10)

        except (asyncio.TimeoutError, aiohttp.ClientError):
            _LOGGER.debug("Error getting IV from %s", generator_url)
            return ''

        content = yield from req.text()

        if req.status != 200:
            _LOGGER.debug(
                "Error getting IV from %s for connection_key %s (%d:%s)",
                generator_url, connection_key, req.status, content)
            return ''

        try:
            return base64.b64decode(content, validate=True)
        except binascii.Error:
            _LOGGER.debug(
                "Error decoding IV for connection_key %s (%d:%s)",
                connection_key, req.status, content)

        return ''

    def send_data(url, connection_key, aes_key, data_str):
        """Send payload data to JITS."""

        publisher_url = "{}/publisher.php".format(url)

        aes_iv = get_aes_iv(url, connection_key)
        if len(aes_iv) == 0:
            return

        encrypter = AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv)

        json_bytes = data_str.encode('utf-8')
        length = 16 - (len(json_bytes) % 16)
        json_bytes += bytes([0]) * length  # add \x00 for padding
        encripted_data = encrypter.encrypt(json_bytes)

        parameters = {'con': connection_key}

        try:
            session = async_get_clientsession(hass)
            with async_timeout.timeout(DEFAULT_TIMEOUT, loop=hass.loop):
                req = yield from session.post(publisher_url, params=parameters,
                                              data=base64.b64encode(
                                                  encripted_data),
                                              timeout=10)

        except (asyncio.TimeoutError, aiohttp.ClientError):
            _LOGGER.error("Error saving data '%s' to %s for connection_key %s "
                          "(timeout)", data_str, publisher_url, connection_key)
            return ''
        except Exception as ex:
            _LOGGER.error("??? %s    >    %s", type(ex).__name__, ex)
        else:
            if req.status_code != 200:
                content = yield from req.text()
                _LOGGER.error("Error saving data '%s' to %s for connection_key"
                              " %s (%d:%s)", data_str, publisher_url,
                              connection_key, req.status, content)

    def update_client(url, client_conf):
        data_dict = {}

        whitelist = client_conf.get(CONF_WHITELIST)
        for entity_id, jits_entity_name in whitelist.items():
            state = hass.states.get(entity_id)

            if state is None or state.state in (
                    STATE_UNKNOWN, '', STATE_UNAVAILABLE):
                continue

            try:
                data_dict[jits_entity_name] = \
                    state_helper.state_as_number(state)
            except ValueError:
                continue

        if data_dict:
            data_str = "{%s}" % ",".join('"{}":"{}"'.format(key, val)
                                         for key, val in data_dict.items())

            send_data(url, client_conf.get(CONF_CONNECTION_KEY),
                      client_conf.get(CONF_AES_KEY), data_str)

    @asyncio.coroutine
    def async_update(time):
        """Iterate trough each client and send whitelisted entities to JITS."""
        for client_conf in conf.get(CONF_CLIENTS):
            update_client(conf.get(CONF_URL), client_conf)

        async_track_point_in_time(hass, async_update, time + timedelta(
            seconds=conf.get(CONF_SCAN_INTERVAL)))

    yield from update(dt_util.utcnow())
    return True
