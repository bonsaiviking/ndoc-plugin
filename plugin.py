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

import sys
import re
import os
import xml.sax
from subprocess import Popen, PIPE
import urllib
import glob
import string
from datetime import datetime
import random

have_pytags = True
try:
    from pytags.etags import EtagFile
except ImportError:
    have_pytags = False

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
reLooseTarget = re.compile(r'^[a-zA-Z0-9\.:][-/,a-zA-Z0-9\.:]*$')
reRange = re.compile(r'(?:-.*\d$|[/\*,]|-$)')
reErr = re.compile(r'^(?P<file>[^:]+):(?P<line>\d+):(?P<text>.*)')
reInteresting = re.compile(r'[^\s\d\-+\'\.:%cdfghilsux]')

class Node():
    def __init__(self):
        self.file = None
        self.line = None
        self.text = None

class Ndoc(callbacks.Plugin):
    """Ask me about Nmap."""
    def __init__(self, irc):
        self.__parent = super(Ndoc, self)
        self.__parent.__init__(irc)
        self.ndir = self.registryValue('nmapDir')
        self.nbin = self.registryValue('nmapBin')
        self.nsrc = self.registryValue('nmapSrc')
        sys.path.append(os.path.join(self.nsrc,'ndiff'))
        from ndiff import Scan
        self.Scan = Scan
        sys.path.append(os.path.join(self.nsrc, 'zenmap'))
        from zenmapCore.ScriptMetadata import ScriptMetadata, get_script_entries
        from zenmapCore.NmapCommand import NmapCommand
        self.NmapCommand = NmapCommand
        from zenmapCore.NmapOptions import NmapOptions
        self.NmapOptions = NmapOptions
        from zenmapCore.UmitConf import PathsConfig
        paths = PathsConfig()
        paths.set_nmap_command_path(self.nbin)
        self.meta = dict( (e.filename, e) for e in get_script_entries(
            os.path.join(self.ndir, 'scripts'),
            os.path.join(self.ndir, 'nselib') )
        )
        self.libs = map(lambda x: os.path.basename(x).split('.')[0], glob.glob(os.path.join(self.ndir, 'nselib', '*.lua*')))
        if have_pytags:
            self.tags = EtagFile()
            self.tags.parse_from_file(os.path.join(self.nsrc, 'TAGS'))
        findproc = Popen("find . -type f \\( -name '*.c' -o -name '*.cc' -o -name '*.h' \\) -print0 | xargs -0 egrep -Hn " +
                "-e '(fatal|error) *\\(' " +
                "-e 'warn(ing)? *\\(' " +
                "-e 'fprintf *\\( *stderr' " +
                "-e '\\<(die|bye|loguser|report|printf) *\\(' ", cwd=self.ndir, shell=True, stdout=PIPE)
        errs, _ = findproc.communicate()
        self.errs = {}
        for line in errs.splitlines():
            m = reErr.match(line)
            if m:
                n = Node()
                n.file = m.group('file')
                n.line = m.group('line')
                n.text = m.group('text')
                for errstr in n.text.split('"')[1::2]: #simple string finder
                    if len(errstr) > 8 and reInteresting.match(errstr):
                        if errstr in self.errs:
                            self.errs[errstr].append(n)
                        else:
                            self.errs[errstr] = [n]
        #TODO: try-catch
        luaman = open(self.registryValue('luaManualTerms'),"r")
        self.luaterms = {}
        for term in map(string.strip, luaman):
            t = term.split("-")
            if t[0] == "pdf":
                self.luaterms[t[1]] = term
            else:
                self.luaterms[term] = term
        luaman.close()
        svnproc = Popen("svn info | awk '$1==\"Revision:\"{print $2}'", cwd=self.nsrc, shell=True, stdout=PIPE)
        self.svnrev, _ = svnproc.communicate()
        self.svnrev = self.svnrev.strip()
        self.lastload = datetime.utcnow()

    def luaterm(self, irc, msg, args, term):
        """<term>

        Returns a link to the Lua 5.2 manual section for <term>."""
        if term in self.luaterms:
            irc.reply("http://www.lua.org/manual/5.2/manual.html#{0}".format(self.luaterms[term]))
        else:
            irc.reply("No such term in Lua 5.2 manual: http://www.lua.org/manual/5.2/manual.html")
    luaterm = wrap(luaterm, ['anything'])

    def description(self, irc, msg, args, script):
        """<script>

        Returns the description of a script"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                irc.reply(self.meta[script].description.replace("\n"," "))
            except KeyError:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    description = wrap(description, ['anything'])

    def author(self, irc, msg, args, script):
        """<script>

        Returns the author of a script"""
        m = reScript.match(script) 
        if m:
            script = "%s.nse" %( m.group('fname') )
            try:
                irc.replies(self.meta[script].author)
            except KeyError:
                irc.reply("Script not found")
        else:
            irc.reply("Bad input")
    author = wrap(author, ['anything'])

    def liblist(self, irc, msg, args):
        """

        Returns the list of NSE libraries."""
        irc.replies(self.libs)
    liblist = wrap(liblist, [])

    def rand(self, irc, msg, args):
        """

        Returns the description and URL of a random script."""
        script = random.choice(self.meta.keys())
        irc.reply(self.meta[script].url)
        irc.reply(self.meta[script].description.replace("\n"," "))
    rand = wrap(rand, [])

    def url(self, irc, msg, args, name):
        """<name>

        Returns a link to the NSEdoc page for <name>. <name> can be a script, library, or library.method."""
        m = re.match(r'(?P<libname>\w+)(?:\.(?P<method>\w+)[\(\)]{0,2})?$', name)
        if m and m.group('libname') in self.libs:
            link = "https://nmap.org/nsedoc/lib/%s.html#%s" %(m.group('libname'), m.group('method') or '')
            irc.reply( link )
        else:
            m = reScript.match(name)
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
        if not m and "." in script and not arg:
            arg = script
            script = script.split(".")[0]
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
        ops = self.NmapOptions()
        ops.executable = self.nbin
        ops["--script-help"] = spec
        ops["-oX"] = "-"
        command_string = ops.render_string()
        nmap_proc = self.NmapCommand(command_string)
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

    def opt(self, irc, msg, args, index, find):
        """[<index>] <find>

        Searches Nmap's quick-help options summary for <find>. If <index> is a number, return results from that offset."""
        if len(find) < 2:
            irc.reply("Search term must be at least 2 characters")
            return
        if index is None:
            index = 0
        if find[0] == "-" and find[1] != "-": # "-X" and not "--long"
            find = " %s" %(find) # avoid matching "--script" when "-s" asked for
        ops = self.NmapOptions()
        ops.executable = self.nbin
        ops["--help"] = True
        nmap_proc = self.NmapCommand(ops.render_string())
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
        results = (filter(lambda l: l.find(find)!= -1, nmap_proc.stdout_file) or ["Nothing found"])
        if len(results) > 5:
            irc.reply("Truncating to 5 results. Be more specific, or use 'index' to see more results")
        for line in results[index:index+5]:
            irc.reply(line.rstrip())
    opt = wrap(opt, [optional('int'),'text'])

    def whois(self, irc, msg, args, target):
        """<target>

        Returns the output of whois-ip for <target>."""
        if not reLooseTarget.match(target) or reRange.search(target):
            irc.reply("Single address only: No ranges or CIDR, sorry")
            return
        ops = self.NmapOptions()
        ops.executable = self.nbin
        ops["--script"] = "whois-ip"
        ops["-sn"] = True
        ops["-Pn"] = True
        ops["-oX"] = "-"
        if ":" in target:
            ops["-6"] = True
        ops.target_specs = [target]
        command_string = ops.render_string()
        nmap_proc = self.NmapCommand(command_string)
        stderr = open("/dev/null", "w")
        try:
            nmap_proc.run_scan(stderr = stderr)
        except Exception, e:
            stderr.close()
            irc.reply("Sorry, could not run whois on that host")
            return
        nmap_proc.command_process.wait()
        stderr.close()
        nmap_proc.stdout_file.seek(0)
        scan = self.Scan()
        scan.load(nmap_proc.stdout_file)
        try:
            host = scan.hosts[0]
        except IndexError:
            irc.reply("Sorry, could not run whois on that host")
            return
        sr = None
        for r in host.script_results:
            if r.id == "whois-ip":
                sr = r
                irc.replies([host.get_id()] + sr.output.split("\n"))
                break
            #elif r.id == "whois-domain":
            #    sr = r
            #    irc.replies([host.format_name()] + sr.output.split("\n"))
        if sr is None:
            irc.reply( "%s: No output." % (host.format_name()) )
            return
    whois = wrap(whois, ['anything'])

    def ipv6(self, irc, msg, args, target):
        """<target>

        Returns the output of address-info.nse for <target>."""
        if not reLooseTarget.match(target) or reRange.search(target):
            irc.reply("Single address only: No ranges or CIDR, sorry")
            return
        ops = self.NmapOptions()
        ops.executable = self.nbin
        ops["-6"] = True
        ops["--script"] = "address-info"
        ops["-sn"] = True
        ops["-Pn"] = True
        ops["-oX"] = "-"
        ops.target_specs = [target]
        command_string = ops.render_string()
        nmap_proc = self.NmapCommand(command_string)
        stderr = open("/dev/null", "w")
        try:
            nmap_proc.run_scan(stderr = stderr)
        except Exception, e:
            stderr.close()
            irc.reply("Sorry, could not run address-info on that host (not an IPv6 address?)")
            return
        nmap_proc.command_process.wait()
        stderr.close()
        nmap_proc.stdout_file.seek(0)
        scan = self.Scan()
        scan.load(nmap_proc.stdout_file)
        try:
            host = scan.hosts[0]
        except IndexError:
            irc.reply("Sorry, could not run address-info on that host (no AAAA record?)")
            return
        sr = None
        for r in host.script_results:
            if r.id == "address-info":
                sr = r
                break
        if sr is None:
            irc.reply( "%s: No output." % (host.format_name()) )
            return
        irc.replies([host.format_name()] + sr.output.split("\n"))
    ipv6 = wrap(ipv6, ['anything'])

    def define(self, irc, msg, args, tag, index):
        """<tag> [<index>]

        Returns up to 3 definitions of <tag> from Nmap's source code, using etags. With <index>, starts from definition <index>."""
        if not have_pytags:
            irc.reply("I couldn't load pytags, sorry.")
            return
        if tag not in self.tags.tags:
            irc.reply("No definition found.")
            return
        tags = self.tags.tags[tag]
        if not index:
            index = 1
        irc.reply("Definitions %d-%d/%d for %s:" % (index, min(index+2, len(tags)), len(tags), tag))
        for t in tags[index-1:index+2]:
            irc.reply("%s:%s: %s" % (t.file, t.line, t.text) )
    define = wrap(define, ['anything', optional('int')])

    def err(self, irc, msg, args, error):
        """<error>

        Returns up to 5 lines of Nmap source that could have generated an <error> message"""
        if len(error) < 3:
            irc.reply("Please search for something longer.")
            return
        limit = 5
        for errstr in self.errs.keys():
            if error in errstr:
                for n in self.errs[errstr]:
                    limit -= 1
                    irc.reply("%s:%s: %s" %(n.file, n.line, n.text) )
                    if limit <= 0:
                        irc.reply("Limit break! Be more specific if you didn't find what you're looking for.")
                        return
    err = wrap(err, ['text'])

    def service(self, irc, msg, args, search):
        """<search>

        Returns the corresponding lines from nmap-services. <search> may be a service name, port, or port/protocol."""
        svcfile = os.path.join(self.ndir, "nmap-services")
        try:
            f = open(svcfile, "r")
        except:
            irc.reply("Can't open nmap-services.")
            return
        reLine = None
        if re.match(r'^\d+(?:/(?:sct|ud|tc)p)?$', search):
            reLine = re.compile(r'^\S+\s+%s[\s/]' %( re.escape(search) ))
        else:
            reLine = re.compile(r'^%s\s' %( re.escape(search) ))
        for l in filter(lambda x: reLine.match(x), f):
            irc.reply(l.rstrip())
    service = wrap(service, ['anything'])

    def proto(self, irc, msg, args, search):
        """<search>

        Returns the corresponding lines from nmap-protocols. <search> may be a proto name or number."""
        svcfile = os.path.join(self.ndir, "nmap-protocols")
        try:
            f = open(svcfile, "r")
        except:
            irc.reply("Can't open nmap-protocols.")
            return
        reLine = None
        if re.match(r'^\d+$', search):
            reLine = re.compile(r'^\S+\s+%s[\s]' %( re.escape(search) ))
        else:
            reLine = re.compile(r'^%s\s' %( re.escape(search) ))
        for l in filter(lambda x: reLine.match(x), f):
            irc.reply(l.rstrip())
    proto = wrap(proto, ['anything'])

    def devlist(self, irc, msg, args, search):
        """<search>

        Returns a link to a Google search for <search> in the nmap-dev mailing list."""
        link = "https://encrypted.google.com/search?"
        irc.reply(link + urllib.urlencode({ 'q': "site:seclists.org inurl:nmap-dev %s" %(search)}))
    devlist = wrap(devlist, ['text'])

    def nsestats(self, irc, msg, args):
        """

        Returns some stats about the Nmap Scripting Engine"""
        uniq_cat = {}
        uniq_author = {}
        for script in self.meta.itervalues():
            for author in script.author:
                uniq_author[author] = 1
            for cat in script.categories:
                uniq_cat[cat] = 1

        stats = "{ns} scripts in {nc} categories by {na} authors. {nl} libraries.".format(
                ns=len(self.meta),
                nc=len(uniq_cat),
                na=len(uniq_author),
                nl=len(self.libs),
                )
        irc.reply(stats)
    nsestats = wrap(nsestats, [])

    def rev(self, irc, msg, args):
        """

        Return the current SVN revision that Ndoc has loaded"""
        irc.reply("I updated to r{} at {} UTC".format(self.svnrev, self.lastload))
    rev = wrap(rev, [])

    def Nhelp(self, irc, msg, args, command):
        """

        Correct usage of the bot."""
        irc.reply("My name is Nhelp, but that's not a command. Did you mean '?{}'".format(command))
    Nhelp = wrap(Nhelp, ['text'])

Class = Ndoc


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
