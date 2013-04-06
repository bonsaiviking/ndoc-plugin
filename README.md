ndoc-plugin
===========

A Supybot plugin for exploring Nmap documentation and usage.

Requirements
------------

* zenmap - This Nmap front-end comes with the Nmap source distribution.
           Ndoc-plugin uses the zenmapCore package, which does not require
           python-gobject.
* ndiff - This is distributed with Nmap, but doesn't install into the Python
          path. Just link it in by hand.
* [pytags](https://github.com/bonsaiviking/py-tags) - This library is
          work-in-progress, but it parses ctags and etags files.
* [Nmap](http://nmap.org/) - Obviously. Ndoc is most useful when you have the
          source code and a full install.
