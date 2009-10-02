"""

  winereg:  access to the Wine Regsitry.

This module provides an identical interface to the _winreg module, but works
entirely by shelling out to Wine's 'regedit' program.  It can thus be used on
a non-Windows box to control registry entries for programs running under Wine.

Currently all work is done using the REGEDIT4 format, which means unicode
support will be basically nonexistent.

"""

import os
import re
import subprocess
import weakref
from tempfile import NamedTemporaryFile


try:
    WindowsError = WindowsError
except NameError:
    class WindowsError(OSError):
        """Dummy WindowsError class."""
    pass


KEY_ALL_ACCESS = 983103
KEY_CREATE_LINK = 32
KEY_CREATE_SUB_KEY = 4
KEY_ENUMERATE_SUB_KEYS = 8
KEY_EXECUTE = 131097
KEY_NOTIFY = 16
KEY_QUERY_VALUE = 1
KEY_READ = 131097
KEY_SET_VALUE = 2
KEY_WOW64_32KEY = 512
KEY_WOW64_64KEY = 256
KEY_WRITE = 131078

REG_BINARY = 3
REG_CREATED_NEW_KEY = 1
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_DWORD_LITTLE_ENDIAN = 4
REG_EXPAND_SZ = 2
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_LEGAL_CHANGE_FILTER = 15
REG_LEGAL_OPTION = 15
REG_LINK = 6
REG_MULTI_SZ = 7
REG_NO_LAZY_FLUSH = 4
REG_NONE = 0
REG_NOTIFY_CHANGE_ATTRIBUTES = 2
REG_NOTIFY_CHANGE_LAST_SET = 4
REG_NOTIFY_CHANGE_NAME = 1
REG_NOTIFY_CHANGE_SECURITY = 8
REG_OPENED_EXISTING_KEY = 2
REG_OPTION_BACKUP_RESTORE = 4
REG_OPTION_CREATE_LINK = 2
REG_OPTION_NON_VOLATILE = 0
REG_OPTION_OPEN_LINK = 8
REG_OPTION_RESERVED = 0
REG_OPTION_VOLATILE = 1
REG_REFRESH_HIVE = 2
REG_RESOURCE_LIST = 8
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_SZ = 1
REG_WHOLE_HIVE_VOLATILE = 1

_ROOT_KEYS = (
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_USER",
    "HKEY_DYN_DATA",
    "HKEY_LOCAL_MACHINE",
    "HKEY_PERFORMANCE_DATA",
    "HKEY_USERS",
)

def _map_type(type):
    """Convert a type constant into its identifier in the .REG file format."""
    if type == REG_SZ:
        return ""
    if type in (REG_DWORD,REG_DWORD_LITTLE_ENDIAN,REG_DWORD_BIG_ENDIAN):
        return "dword:"
    if type == REG_BINARY:
        return "hex:"
    if type == REG_MULTI_SZ:
        return "hex(7):"
    if type == REG_EXPAND_SZ:
        return "hex(2):"
    raise ValueError

def _map_data(data,type):
    """Convert a value into its representation in the .REG file format."""
    if type == REG_SZ:
        return data
    if type in (REG_DWORD,REG_DWORD_LITTLE_ENDIAN,REG_DWORD_BIG_ENDIAN):
        return hex(data)[2:].rjust(8,'0')
    if type == REG_BINARY:
        return ",".join(hex(ord(b))[2:] for b in data)
    if type == REG_MULTI_SZ:
        return "00".join(_map_data(d,REG_BINARY) for d in data)
    if type == REG_EXPAND_SZ:
        return ",".join(hex(ord(b))[2:] for b in data)
    raise ValueError

def _unmap_type(type):
    """Convert a type constant from its identifier in the .REG file format."""
    if not type:
        return REG_SZ
    if type == "dword:":
        return REG_DWORD
    if type == "hex:":
        return REG_BINARY
    if type == "hex(7):":
        return REG_MULTI_SZ
    if type == "hex(2):":
        return REG_EXPAND_SZ
    raise ValueError

def _unmap_data(data,type):
    """Convert a value from its representation in the .REG file format."""
    if type == REG_SZ:
        return data
    if type in (REG_DWORD,REG_DWORD_LITTLE_ENDIAN,REG_DWORD_BIG_ENDIAN):
        return int(data,16)
    if type == REG_BINARY:
        return "".join(chr(int(c,16)) for c in data.split(",") if c)
    if type == REG_MULTI_SZ:
        return [_unmap_data(d,REG_BINARY) for d in data.split("00")]
    if type == REG_EXPAND_SZ:
        return "".join(chr(int(c,16)) for c in data.split(",") if c)
    raise ValueError



class PyHKEY(object):
    """Object representing an individual registry key.

    This class contains the workhorse logic for the module - shelling out
    to `regedit` and parsing back the required values.  You can create them
    directly if you like, but should probably get them throuw a WineReg 
    instance so that the environment will be correctly set.
    """

    #  For compatability with _winreg, we allow keys to be
    #  retreived using an integer id.
    _HANDLES = weakref.WeakValueDictionary()

    def __init__(self,wineprefix,path):
        self._valid = True
        self.wineprefix = wineprefix
        self.path = path
        self._HANDLES[int(self)] = self

    @classmethod
    def lookup(cls,key):
        if not isinstance(key,cls):
            key = cls._HANDLES[int(key)]
        if not key._valid:
            raise WindowsError
        return key

    #  Methods for compatability with _winreg.PyHKEY

    def Close(self):
        self._valid = False

    def Detach(self):
        raise NotImplementedError

    def __nonzero__(self):
        return not self._valid

    def __int__(self):
        return id(self)

    def __enter__(self):
        return self

    def __exit__(self,*exc_info):
        self.Close()

    #  Methods actually implementing functionality

    def _run_regedit(self,*args):
        """Shell out to `regedit` with the given arguments."""
        cmd = ["regedit"]
        cmd.extend(args)
        if self.wineprefix is not None:
            env = {"WINEPREFIX":self.wineprefix}
        else:
            env = None
        null = open(os.devnull)
        if subprocess.call(cmd,env=env,stdout=null,stderr=null) != 0:
            raise WindowsError

    def _regedit(self,contents):
        """Apply the given .REG file commands to the registry."""
        tf = NamedTemporaryFile()
        tf.write("REGEDIT4\n\n")
        tf.write(contents)
        tf.write("\n\n")
        tf.flush()
        self._run_regedit(tf.name)

    def _regread(self,path):
        """Read contents of given key from the registry.

        The result is a generator of (key,name,data,type) tuples.  For
        the keys themselves each of name, data and type will be None.
        """
        tf = NamedTemporaryFile()
        self._run_regedit("/E",tf.name,path)
        tf.seek(0)
        tf.readline()
        (key,name,data,type) = (None,None,None,None)
        for ln in tf:
            if not ln:
                continue
            if ln.startswith("["):
                 key = ln.strip().strip("[]").strip("\"")
                 (name,data,type) = (None,None,None)
            else:
                val_re = r'^"?(\@|[^"]+)"?="?(([a-zA-Z0-9\(\)]+:)?)([^"]+)"?$'
                m = re.match(val_re,ln.strip())
                if not m:
                    continue
                (name,type,_,data) = m.groups()
                if name == "@":
                    name = ""
                type = _unmap_type(type)
                data = _unmap_data(data,type)
            yield (key,name,data,type)

    def join(self,sub_key):
        """Get a subkey of this key."""
        sub_key = sub_key.strip("\\")
        if not sub_key:
            return self
        return PyHKEY(self.wineprefix,self.path + "\\" + sub_key)

    def create(self):
        """Ensure key exists, creating if not."""
        self._regedit("[%s]" % (self.path,))

    def delete(self):
        """Delete this key."""
        self._regedit("[-%s]" % (self.path,))

    def delete_value(self,value):
        """Delete a value from this key."""
        self._regedit("[%s]\n\"%s\"=-" % (self.path,value,))

    def nth_subkey(self,n):
        """Get the n'th subkey from this key."""
        num_seen = 0
        for (key,name,data,type) in self._regread(self.path):
            if name is not None:
                continue
            if key != self.path and "\\" not in key[len(self.path)+1:]:
                num_seen += 1
                if num_seen > n:
                    return key
        else:
            raise WindowsError

    def nth_value(self,n):
        """Get the n'th value from this key."""
        num_seen = 0
        for (key,name,data,type) in self._regread(self.path):
            if key != self.path or not name:
                continue
            num_seen += 1
            if num_seen > n:
                return (name,data,type)
        else:
            raise WindowsError

    def check(self):
        """Check whether this key exists."""
        for ln in self._regread(self.path):
            break

    def get_info(self):
        """Get info about this key.

        Returns a tuple (num_subkeys,num_values,modified_time), although
        on Wine the modified_time is always zero.
        """
        num_subkeys = 0
        num_values = 0
        for (key,name,data,type) in self._regread(self.path):
            if key == self.path and name is not None:
                num_values += 1
            elif name is None and key != self.path:
                if "\\" not in key[len(self.path)+1:]:
                    num_subkeys += 1
        return (num_subkeys,num_values,0)

    def get_value(self,value_name):
        """Get a value from this key."""
        for (key,name,data,type) in self._regread(self.path):
            if key == self.path and name == value_name:
                return (data,type)
        else:
            raise WindowsError

    def set_value(self,name,data,type):
        """Set a value on this key."""
        data = _map_data(data,type)
        type = _map_type(type)
        if name == "":
            self._regedit("[%s]\n@=\"%s%s\"" % (self.path,type,data))
        else:
            self._regedit("[%s]\n\"%s\"=\"%s%s\"" % (self.path,name,type,data))

    def dump(self,filename):
        """Dump this key and all subkeys to a file."""
        self._run_regedit("/E",filename,self.path)

    def load(self,filename):
        """Load this key from a file."""
        self._run_regedit(filename)
            


class WineReg(object):
    """Class providing access to a Wine registry.

    Since Wine has a concept of 'prefixes' that can each have their own
    private registry, it can be useful to allow editing of several different
    registries within the one program.  If you only want to edit the default
    Wine registry, don't create an instance of this class - just use the
    corresponding methods exported directly in the winereg module.
    """

    def __init__(self,wineprefix=None):
        self.wineprefix = wineprefix
        for root_key in _ROOT_KEYS:
            setattr(self,root_key,PyHKEY(self.wineprefix,root_key))

    def CloseKey(self,hkey):
        """Close a previously opened registry key."""
        PyHKEY.lookup(hkey).Close()

    def ConnectRegistry(self,computer_name,key):
        """Connect to a predefined registry handle on another computer.

        This isn't supported by winereg.
        """
        raise WindowsError

    def CreateKey(self,key,sub_key):
        """Create or open the specified key."""
        new_key = PyHKEY.lookup(key).join(sub_key)
        new_key.create()
        return new_key

    def DeleteKey(self,key,sub_key):
        """Delete the specific key."""
        key = PyHKEY.lookup(key).join(sub_key)
        key.check()
        try:
            key.nth_subkey(0)
        except WindowsError:
            key.delete()
        else:
            raise WindowsError

    def DeleteValue(self,key,value):
        """Remove a named value from the registry key."""
        PyHKEY.lookup(key).delete_value(value)

    def EnumKey(self,key,index):
        """Enumerate subkeys of an open registry key."""
        return PyHKEY.lookup(key).nth_subkey(index).split("\\")[-1]
        
    def EnumValue(self,key,index):
        """Enumerate values of an open registry key."""
        return PyHKEY.lookup(key).nth_value(index)

    def ExpandEnvironmentStrings(self,value):
        """Expand environment vars in a string.  Currently not implemented."""
        raise NotImplementedError

    def FlushKey(self,key):
        """Flush a key to disk.  This is a no-op for winereg."""
        pass

    def LoadKey(self,key,sub_key,file_name):
        """Create a subkey under the specified key and populate from file."""
        PyHKEY.lookup(key).join(sub_key).load(file_name)

    def OpenKey(self,key,sub_key,res=0,sam=KEY_READ):
        """Open the specified key."""
        key = PyHKEY.lookup(key).join(sub_key)
        key.check()
        return key

    def OpenKeyEx(self,key,sub_key,res,sam):
        """Compatability function, just calls OpenKey."""
        return self.OpenKey(key,sub_key,res,sam)

    def QueryInfoKey(self,key):
        """Return information about a key."""
        return PyHKEY.lookup(key).get_info()

    def QueryValue(self,key,sub_key):
        """Retreive the unnamed value for a key, as a string."""
        return PyHKEY.lookup(key).join(sub_key).get_value("")[0]

    def QueryValueEx(self,key,value_name):
        """Retrieve the type and data for a specified key\\value."""
        return PyHKEY.lookup(key).get_value(value_name)

    def SaveKey(self,key,file_name):
        """Export a key to the specified file."""
        PyHKEY.lookup(key).dump(file_name)

    def SetValue(self,key,sub_key,type,value):
        """Associate a value with a specified key."""
        PyHKEY.lookup(key).join(sub_key).set_value("",value,type)

    def SetValueEx(self,key,value_name,reserved,type,value):
        """Store data in the value field of a key."""
        PyHKEY.lookup(key).set_value(value_name,value,type)


#  Make default implementation available in root namespace
_INSTANCE = WineReg()
for nm in dir(_INSTANCE):
    if nm.startswith("_"):
       continue
    if nm.startswith("wine"):
       continue
    globals()[nm] = getattr(_INSTANCE,nm)
    
