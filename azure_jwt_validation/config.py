import os
import json
import logging
from json.decoder import JSONDecodeError
from typing import List, Dict, Union

import requests
from requests.exceptions import RequestException

from .exceptions import TokenValidationException
from .resources import get_pkg_resource_path

logger = logging.getLogger(__name__)

PACKAGE = 'azure_jwt_validation'
OPENID_CONFIG_FILENAME = 'openid_config.json'
PUBLIC_KEYS_FILENAME = 'public_keys.json'
CONFIG_CACHE_PATH = os.environ.get('AZURE_JWT_CONFIG_CACHE', None)

config_cache = {}


def get_open_id_configuration_from_azure(ad_tenant, openid_configuration_url=None):
    """Given an AD tenant, returns the open id configuration from Azure.

    Args:
        ad_tenant: Your ad tenant. For example yourtenant.onmicrosoft.com
        openid_configuration_url: URL for the tenant's OpenID configuration (default: usual AD tenant URL)

    .. note:: In production only run this periodically and cache the result.

    Raises:
        :exc:`TokenValidationException`: When the configuration cannot be retrieved.
    """
    if openid_configuration_url is None:
        openid_configuration_url = f'https://login.microsoftonline.com/{ad_tenant}/.well-known/openid-configuration'
    try:
        response = requests.get(openid_configuration_url)
        return response.json()
    except RequestException as err:
        raise TokenValidationException(
            f'Could not retrieve openid-configuration from Microsoft. Details: \n {err}'
        )


def update_open_id_config(ad_tenant: str, openid_configuration_url=None, config_cache_path=None):
    """Given an AD tenant, updates the cached package resource openid_config.json.

    Args:
        ad_tenant: Your ad tenant. For example yourtenant.onmicrosoft.com
        openid_configuration_url: URL for the tenant's OpenID configuration (default: usual AD tenant URL)

    .. note:: In production only run this periodically and cache the result.

    Raises:
        :exc:`TokenValidationException`: When the configuration cannot be retrieved.
    """
    data = get_open_id_configuration_from_azure(ad_tenant, openid_configuration_url)
    config_cache = get_cache(config_cache_path)
    config_cache['openid_config'] = data

    if config_cache_path is None:
        path = get_pkg_resource_path(PACKAGE, 'openid_config.json')
        path.write_text(json.dumps(data, indent=2))
    else:
        path = os.path.join(config_cache_path, 'openid_config.json')
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    return data


def _get_resource_obj(name: str):
    p = get_pkg_resource_path(PACKAGE, name)
    return json.loads(p.read_text())


def get_cached_open_id_config() -> dict:
    """Returns the open_id config from the openid_config.json file or cache."""
    try:
        return get_cache()['openid_config']
    except KeyError:
        raise TokenValidationException(
            'Open id config not found in cache or openid_config.json. '
            'Try refreshing the config with the update_open_id_config function.'
        )


def get_cached_public_keys() -> List[Dict]:
    """Returns the public keys from the public_keys.json file or cache."""
    try:
        return get_cache()['public_keys']
    except KeyError:
        raise TokenValidationException(
            'Public keys not found in cache or public_keys.json. '
            'Try refreshing the keys with the update_current_microsoft_public_keys_file function.'
        )


def get_valid_issuer():
    """Get the valid ``iss`` value from the open_id configuration.
    """
    openid_config = get_cached_open_id_config()
    try:
        return openid_config['issuer']
    except KeyError:
        raise TokenValidationException('Could not obtain valid issuer from open id configuration.')


def get_current_microsoft_public_keys(ms_signing_key_url='https://login.microsoftonline.com/common/discovery/keys'):
    """Returns the list of currently in use public keys.

    Args:
        ms_signing_key_url: The known url for the public keys

    .. note::

        These guys are updated approximately every 24 hours. We can save them
        to the db/file/etc and update them periodically or on failure.
    """
    response = requests.get(ms_signing_key_url)
    keys_dict = response.json()
    return keys_dict['keys']


def update_current_microsoft_public_keys_file(
        ms_signing_key_url='https://login.microsoftonline.com/common/discovery/keys',
        config_cache_path=None
    ):
    """Writes the list of currently in use public keys to the package resource public_keys.json."""
    key_list = get_current_microsoft_public_keys(ms_signing_key_url)
    config_cache = get_cache(config_cache_path)
    config_cache['public_keys'] = key_list

    if config_cache_path is None:
        path = get_pkg_resource_path(PACKAGE, PUBLIC_KEYS_FILENAME)
        path.write_text(json.dumps(key_list, indent=2))
    else:
        path = os.path.join(config_cache_path, PUBLIC_KEYS_FILENAME)
        with open(path, 'w') as f:
            json.dump(key_list, f, indent=2)

    return key_list


def _populate_cache_from_file(key: str, config_cache_path: Union[str, None]):
    """Try to update the config cache from the files.

    Args:
        key: Either 'openid_config' or 'public_keys'
    """
    if key not in ('openid_config', 'public_keys'):
        raise ValueError(
            'Key must be either openid_config or public_keys'
        )
    file_name = f'{key}.json'

    try:
        if config_cache_path is None:
            config_cache[key] = _get_resource_obj(file_name)
        else:
            with open(os.path.join(config_cache_path, file_name), 'r') as f:
                config_cache[key] = json.load(f)
    except JSONDecodeError:
        pass



def get_cache(config_cache_path=None, reload=False):
    global config_cache

    # FIXME: make this whole module an object
    if len(config_cache) == 0 or reload:
        if config_cache_path is None:
            config_cache_path = CONFIG_CACHE_PATH
        # Useful first time the module loads
        try:
            _populate_cache_from_file('openid_config', config_cache_path)
            _populate_cache_from_file('public_keys', config_cache_path)
        except FileNotFoundError:
            logger.warning(f'Config not yet cached.')
        else:
            expected = ('openid_config', 'public_keys')

            for config_name in expected:
                exists = config_cache.get(config_name)
                if not exists:
                    logger.warning(f'Expected config {config_name} not found please call the appropriate setup function.')

    return config_cache
