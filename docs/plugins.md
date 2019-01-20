Plugins
===

Bigacme supports plugins, to be able to use DNS validation. This is useful for sites that are not available on the internet, or if port 80 is not available for http.

A plugin should subclass the BigacmePlugin class, see [plugin.py](../bigacme/plugin.py). Everything should be pretty straith forward - it has similarities to certbot plugins.

To register your plugin, use [setuptools entry points](http://setuptools.readthedocs.io/en/latest/pkg_resources.html#entry-points) using the 'bigacme.plugins' group. Configuration for the plugin should be placed in the config.ini file, in the "Plugin" section. Like so:

```
[Plugin]
url = dns-server.example.com
token = jdksjfkdjsfojdsofjdsf
```

These config parameters will be used to initialize the plugin (sent as kwargs).

For an example plugin, see [bigacme-dummy-plugin](https://github.com/magnuswatn/bigacme-dummy-plugin).
