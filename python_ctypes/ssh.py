import sys
import enum
import ctypes
import ctypes.util

class SSH_ENUMS(enum.Enum):
    
    #session creation 
    SSH_OK=0
    SSH_ERROR=-1
    SSH_AGAIN=-2
    SSH_EOF=-127

    #ssh options
    SSH_OPTIONS_HOST=0
    SSH_OPTIONS_PORT=1
    SSH_OPTIONS_PORT_STR=2
    SSH_OPTIONS_FD=3
    SSH_OPTIONS_USER=4
    SSH_OPTIONS_SSH_DIR=5
    SSH_OPTIONS_IDENTITY=6
    SSH_OPTIONS_ADD_IDENTITY=7
    SSH_OPTIONS_KNOWNHOSTS=8
    SSH_OPTIONS_TIMEOUT=9
    SSH_OPTIONS_TIMEOUT_USEC=10
    SSH_OPTIONS_SSH1=11
    SSH_OPTIONS_SSH2=12
    SSH_OPTIONS_LOG_VERBOSITY=13
    SSH_OPTIONS_LOG_VERBOSITY_STR=14
    SSH_OPTIONS_CIPHERS_C_S=15
    SSH_OPTIONS_CIPHERS_S_C=16
    SSH_OPTIONS_COMPRESSION_C_S=17
    SSH_OPTIONS_COMPRESSION_S_C=18
    SSH_OPTIONS_PROXYCOMMAND=19
    SSH_OPTIONS_BINDADDR=20
    SSH_OPTIONS_STRICTHOSTKEYCHECK=21
    SSH_OPTIONS_COMPRESSION=22
    SSH_OPTIONS_COMPRESSION_LEVEL=23
    SSH_OPTIONS_KEY_EXCHANGE=24
    SSH_OPTIONS_HOSTKEYS=25
    SSH_OPTIONS_GSSAPI_SERVER_IDENTITY=26
    SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY=27
    SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIAS=28
    SSH_OPTIONS_HMAC_C_S=29
    SSH_OPTIONS_HMAC_S_C=30

    #sftp file open
    O_RDONLY=0
    O_WRONLY=1
    O_RDWR=2
    O_APPEND=3
    O_CREAT=4
    O_DSYNC=5
    O_EXCL=6
    O_NOCTTY=7
    O_NONBLOCK=8
    O_RSYNC=9
    O_SYNC=10
    O_TRUNC=11

class SSH_VAR_LOADER:
    values = SSH_ENUMS.__members__
    for value in values.keys():
       globals()[value] = values[value].value

def include(name):
    getter = ctypes.util.find_library
    setter = ctypes.CDLL
    return setter(getter(name))

class SFTP_SSH_STRING(ctypes.Structure):
    __fields__ = [ ('size',ctypes.c_uint32),('data',ctypes.c_ubyte) ]

class SFTP_STAT_STRUCT(ctypes.Structure):
    _fields_ = [
                ("name", ctypes.c_char_p),
                ("longname", ctypes.c_char_p),
                ("flags", ctypes.c_uint32),
                ("type", ctypes.c_uint8),
                ("size", ctypes.c_uint64),
                ("uid",ctypes.c_uint32),
                ("gid",ctypes.c_uint32),
                ("owner", ctypes.c_char_p),
                ("group", ctypes.c_char_p),
                ("permissions", ctypes.c_uint32),
                ('atime64',ctypes.c_uint64),
                ('atime',ctypes.c_uint32),
                ('atime_nseconds',ctypes.c_uint32),
                ('createtime',ctypes.c_uint64),
                ('createtime_nseconds',ctypes.c_uint32),
                ('mtime64',ctypes.c_uint64),
                ('mtime',ctypes.c_uint32),
                ('mtime_nseconds',ctypes.c_uint32),
                ('acl',SFTP_SSH_STRING),
                ('extended_count',ctypes.c_uint32),
                ('extended_type',SFTP_SSH_STRING),
                ('extended_data',SFTP_SSH_STRING)
                ]


class SSH:
    def __init__(self):
        self._masquerade(include('ssh'))

    def _masquerade(self,origin):
        self.__class__ = type(origin.__class__.__name__,(self.__class__,origin.__class__),{})
        self.__dict__ = origin.__dict__

    def __del__(self):
        self.ssh_disconnect(self.session)
        self.ssh_free(self.session)

    def _open_session(self):
        self.session = self.ssh_new()
        if not self.session:
            raise Exception('Unable to create a session object for a connection')

    def _set_verbosity(self,verbosity):
        self.ssh_options_set(self.session,SSH_OPTIONS_LOG_VERBOSITY,str(verbosity).encode())

    def _set_hostname(self,hostname):
        self.ssh_options_set(self.session,SSH_OPTIONS_HOST,str(hostname).encode())

    def _connect(self):
        rc = self.ssh_connect(self.session)
        if rc != SSH_OK:
            self.free(self.session)
            raise Exception('Connection to target has failed')

    def _authenticate(self,username,password):
        self.ssh_userauth_password(self.session,str(username).encode(),str(password).encode())

    def connect(self,hostname,username,password,verbosity=2):
        self._open_session()
        self._set_verbosity(verbosity)
        self._set_hostname(hostname)
        self._connect()
        self._authenticate(username,password)

    def _open_channel(self):
        self.channel = self.ssh_channel_new(self.session)
        self.ssh_channel_open_session(self.channel)

    def _read_channel(self):
        response = ""
        while (self.ssh_channel_is_open(self.channel) and not self.ssh_channel_is_eof(self.channel)):
            buff = ctypes.create_string_buffer(256) 
            latest_resp = self.ssh_channel_read(self.channel,buff,256,0)
            response += buff.value.decode()
        return response

    def exec_command(self,command):
        self._open_channel()
        self.ssh_channel_request_exec(self.channel,str(command).encode())
        resp = self._read_channel()
        return resp

    def _open_sftp(self):
        self.sftp = self.sftp_new(self.session)
        if not self.sftp:
            raise Exception("Error allocating SFTP session")

    def _init_sftp(self):
        rc = self.sftp_init(self.sftp)
        if rc != SSH_OK:
            self.sftp_free(self.sftp)
            raise Exception("Error initializing SFTP session")

    def open_sftp(self):
        self._open_sftp()
        self._init_sftp()

    def _sftp_open_file(self,file_path):
        file = self.sftp_open(self.sftp,file_path.encode(),O_RDONLY,0)
        if not file:
            raise Exception("Can't open file for reading")
        return file

    def _sftp_read_file(self,file_path):
        MAX_XFER_BUF_SIZE=16384
        buff = ctypes.create_string_buffer(MAX_XFER_BUF_SIZE)
        file = self._sftp_open_file(file_path)
        while True:
            resp = self.sftp_read(file, buff, MAX_XFER_BUF_SIZE);
            if resp ==0: break
            elif resp<0: raise Exception("Error while reading file")
        return buff.value.decode()

    def _sftp_stat(self,file_path):
        opened_file = self._sftp_open_file(file_path)
        stats = self.sftp_fstat(opened_file)
        data = SFTP_STAT_STRUCT.from_address(stats)
        if not stats:
            raise Exception("Unable to stat file")
        else:
            print(
                '\nname: ',data.name,
                '\nlongname: ',data.longname,
                '\nflags: ',data.flags,
                '\ntype: ',data.type,
                '\nsize: ',data.size,
                '\nuid: ',data.uid,
                '\ngid: ',data.gid,
                '\nowner: ',data.owner,
                '\ngroup: ',data.group,
                '\npermissions: ',int(oct(data.permissions)[-3:]),
                '\natime64: ',data.atime64,
                '\natime: ',data.atime,
                '\natime_nseconds: ',data.atime_nseconds,
                '\ncreatetime: ',data.createtime,
                '\ncreatetime_nseconds: ',data.createtime_nseconds,
                '\nmtime64: ',data.mtime64,
                '\nmtime: ',data.mtime,
                '\nmtime_nseconds: ',data.mtime_nseconds,
                '\nacl: ',data.acl,
                '\nextended_count: ',data.extended_count,
                '\nextended_type: ',data.extended_type,
                '\nextended_data: ',data.extended_data)


A = SSH()
A.connect('127.0.0.1','zorian','Aa100100',verbosity=0)
Z = A.exec_command('mkdir /tmp/testtt')
print(Z)
#A.open_sftp()
#A._sftp_stat('/tmp/test')
#Z = A._sftp_read_file('/tmp/long')
