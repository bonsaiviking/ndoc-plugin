###
# Copyright (c) 2013, Daniel Miller
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

###

import supybot.utils as utils
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
import supybot.log as log

from zenmapCore.ScriptMetadata import ScriptMetadata, get_script_entries
from zenmapCore.NmapCommand import NmapCommand
from zenmapCore.NmapOptions import NmapOptions
import re
import os
import xml.sax

### Copied from Nmap 6.25 source: zenmap/zenmapGUI/ScriptInterface.py
class ScriptHelpXMLContentHandler (xml.sax.handler.ContentHandler):
    """A very simple parser for --script-help XML output. This could extract
    other information like categories and description, but all it gets is
    filenames. (ScriptMetadata gets the other information.)"""
    def __init__(self):
        self.script_filenames = []
        self.scripts_dir = None
        self.nselib_dir = None

    def startElement(self, name, attrs):
        if name == u"directory":
            if not attrs.has_key(u"name"):
                raise ValueError(u"\"directory\" element did not have \"name\" attribute")
            dirname = attrs[u"name"]
            if not attrs.has_key(u"path"):
                raise ValueError(u"\"directory\" element did not have \"path\" attribute")
            path = attrs[u"path"]
            if dirname == u"scripts":
                self.scripts_dir = path
            elif dirname == u"nselib":
                self.nselib_dir = path
            else:
                # Ignore.
                pass
        elif name == u"script":
            if not attrs.has_key(u"filename"):
                raise ValueError(u"\"script\" element did not have \"filename\" attribute")
            self.script_filenames.append(attrs[u"filename"])

    @staticmethod
    def parse_nmap_script_help(f):
        parser = xml.sax.make_parser()
        handler = ScriptHelpXMLContentHandler()
        parser.setContentHandler(handler)
        parser.parse(f)
        return handler
### END Copied from Nmap 6.25 source

reScript = re.compile(r'(?P<fname>[\-a-z0-9]+)(?:.nse)?$')

class Ndoc(callbacks.Plugin):
    """Ask me about Nmap."""
    def __init__(self, irc):
        self.__parent = super(Ndoc, self)
        self.__parent.__init__(irc)
        self.ndir = self.registryValue('nmapDir')
        self.nbin = self.registryValue('nmapBin')
        self.meta = dict( (e.filename, e) for e in get_script_entries(
            os.path.join(self.ndir, 'scripts'),
            os.path.join(self.ndir, 'nselib') )
        )

    def author(self, irc, msg, args, script):
        """<script>

        Returns the author of a script"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                irc.reply(self.meta[script].author)
            except KeyError:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    author = wrap(author, ['anything'])

    def url(self, irc, msg, args, script):
        """<script>

        Returns the url of a script"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                irc.reply(self.meta[script].url)
            except KeyError:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    url = wrap(url, ['anything'])

    def usage(self, irc, msg, args, script):
        """<script>

        Returns the usage of a script"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                for line in (self.meta[script].usage or "No usage available").split("\n"):
                    if not line:
                        continue
                    irc.reply( line )
            except KeyError:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    usage = wrap(usage, ['anything'])

    def categories(self, irc, msg, args, script):
        """<script>

        Returns the categories of a script"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                cat = ( self.meta[script].categories or ["No categories available"])
                irc.replies(cat)
            except KeyError:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    categories = wrap(categories, ['anything'])

    def requires(self, irc, msg, args, script):
        """<script>

        Returns the libraries that a script requires"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            if script in self.meta:
                req = ScriptMetadata.get_requires(os.path.join(self.ndir, 'scripts', script)) or ["No requires available"]
                irc.replies(req)
            else:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    requires = wrap(requires, ['anything'])

    def args(self, irc, msg, args, script, arg):
        """<script> [<arg>]

        Returns the --script-args that a script accepts. With <arg>, returns the description of <arg>."""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                args = ( self.meta[script].arguments or [["No script arguments available"]])
            except KeyError:
                irc.reply("Script not found")
                return
            if arg:
                for a in args:
                    if a[0] == arg:
                        irc.reply(re.sub(r'\s+', ' ', (a[1] or "No description"), flags=re.M))
            else:
                irc.replies(a[0] for a in args)
        else:
            irc.reply("Bad input")
    args = wrap(args, ['anything',optional('anything')])

    def expand(self, irc, msg, args, spec):
        """<spec>

        Returns the list of scripts that <spec> will attempt to run."""
        ops = NmapOptions()
        ops.executable = self.nbin
        ops["--script-help"] = spec
        ops["-oX"] = "-"
        command_string = ops.render_string()
        nmap_proc = NmapCommand(command_string)
        stderr = open("/dev/null", "w")
        try:
            nmap_proc.run_scan(stderr = stderr)
        except Exception, e:
            stderr.close()
            irc.reply("Failed to expand")
            return
        nmap_proc.command_process.wait()
        stderr.close()
        nmap_proc.stdout_file.seek(0)
        result = ScriptHelpXMLContentHandler.parse_nmap_script_help(nmap_proc.stdout_file)
        irc.replies(map(lambda f: reScript.search(f).group("fname"), result.script_filenames) or ["No scripts match"])
    expand = wrap(expand, ['text'])

    def opt(self, irc, msg, args, find):
        """<find>

        Searches Nmap's quick-help options summary for <find>."""
        if len(find) < 2:
            irc.reply("Search term must be at least 2 characters")
            return
        if find[0] == "-" and find[1] != "-": # "-X" and not "--long"
            find = " %s" %(find) # avoid matching "--script" when "-s" asked for
        ops = NmapOptions()
        ops.executable = self.nbin
        ops["--help"] = True
        nmap_proc = NmapCommand(ops.render_string())
        stderr = open("/dev/null", "w")
        try:
            nmap_proc.run_scan(stderr = stderr)
        except Exception, e:
            stderr.close()
            irc.reply("Failed to run")
            return
        nmap_proc.command_process.wait()
        stderr.close()
        nmap_proc.stdout_file.seek(0)
        for line in (filter(lambda l: l.find(find)!= -1, nmap_proc.stdout_file) or ["Nothing found"]):
            irc.reply(line.rstrip())
    opt = wrap(opt, ['text'])

Class = Ndoc


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
