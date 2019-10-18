try:
    from functools import lru_cache
except ImportError:  # pragma: no cover
    from functools32 import lru_cache

import os
from abc import abstractproperty
from importlib import import_module

from detect_secrets.plugins.base import BasePlugin


def _change_custom_plugin_paths_to_tuple(custom_plugin_paths_function):
    """
    :type custom_plugin_paths_function: function
    A function that takes one argument named custom_plugin_paths

    :returns: function
    The custom_plugin_paths_function with it's arg changed to a tuple
    """
    def wrapper_of_custom_plugin_paths_function(custom_plugin_paths):
        return custom_plugin_paths_function(tuple(custom_plugin_paths))

    return wrapper_of_custom_plugin_paths_function


@_change_custom_plugin_paths_to_tuple
@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class_name(custom_plugin_paths):
    """Returns dictionary of secret_type => plugin classname"""
    return {
        plugin.secret_type: name
        for name, plugin in import_plugins(custom_plugin_paths).items()
    }


@_change_custom_plugin_paths_to_tuple
@lru_cache(maxsize=1)
def import_plugins(custom_plugin_paths):
    """
    :type custom_plugin_paths: tuple(str,)
    :param custom_plugin_paths: possibly empty tuple of paths that have custom plugins.

    :rtype: Dict[str, Type[TypeVar('Plugin', bound=BasePlugin)]]
    """
    plugin_paths = ['detect_secrets/plugins'] + list(custom_plugin_paths)
    plugin_modules = []
    for plugin_path in plugin_paths:
        for root, _, files in os.walk(  # pragma: no cover (Always breaks)
            plugin_path,
        ):
            for filename in files:
                if (
                    not filename.startswith('_')
                    and filename.endswith('.py')
                ):
                    full_path = os.path.join(root, filename)
                    # [:-3] for removing '.py'
                    module_name = full_path[:-3].replace('/', '.')
                    plugin_modules.append(
                        module_name,
                    )
            # Do not traverse more than 1 level
            break

    plugins = {}
    for module_name in plugin_modules:
        module = import_module((module_name))
        for attr_name in filter(
            lambda attr_name: not attr_name.startswith('_'),
            dir(module),
        ):
            attr = getattr(module, attr_name)

            # Skip attr's that are not valid plugins
            try:
                if not issubclass(attr, BasePlugin):
                    continue
            except TypeError:
                # Occurs when attr is not a class type
                continue
            # Use this as a heuristic to determine abstract classes
            if isinstance(attr.secret_type, abstractproperty):
                continue

            plugins[attr_name] = attr

    return plugins
