import paramiko

import gzip
import io
import os
import re

import ctypes
import ctypes.util

class BufferContentType:
    """
    Emultaion Definition - bash file command on buffer object i.e open(file).read()
    """
    def __init__(self):
        self._load_libmagic()
        self._handle_magic_config(0x000120)

    def __call__(self,fh):
        file_type_list_str = self._get_file_magic_types(fh)
        file_type_list = self._parse_magic_types(file_type_list_str)
        return file_type_list

    def _load_libmagic(self,):
        dll = ctypes.util.find_library('magic')
        self.libmagic = ctypes.CDLL(dll)

    def _handle_magic_config(self,mime):
        self.libmagic.magic_buffer.restype = ctypes.c_char_p #return str instead of int
        cookie = self.libmagic.magic_open(mime)
        self.libmagic.magic_load(cookie,None)
        self.cookie = cookie

    def _get_file_magic_types(self,fh):
        #filename = filename.encode()
        fh = fh.read().encode('utf-8', errors='replace')
        file_type_list_str = self.libmagic.magic_buffer(self.cookie, fh, len(fh))
        return file_type_list_str

    def _parse_magic_types(self,types):
        if types:
            types = types.decode('utf-8')
            types = types.replace('\n-',',').replace('-','')
            types = [ i.strip() for i in types.split(',') ]
        return types

class Tail:
    def __init__(self,host,username,password,log_patterns=None):
        """
            log_patterns - list - for adding log rotation formats for file name change upon roll. 
        """
        self.log_patterns = log_patterns
        self.host = host
        self.username = username
        self.password = password
        self._connect()
        self.missing = None
        self.sub_file = None
        self.sftp_client = None

    def _connect(self):
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host,username=self.username,password=self.password)
        self.sftp_client = self.client.open_sftp()
   
    def __del__(self):
        if self.sftp_client:
          self.sftp_client.close()
        self.client.close()

    def _exists(self,file_path):
        """ 
        Emulation Definition - os.exists
        """
        directory,file_name = os.path.split(os.path.abspath(file_path))
        remote_files = self.sftp_client.listdir(directory)
        if file_name in remote_files:
            return True
        else:
            return False

    def _stat(self,file_path):
        """
        Emulation Definition - os.stat
        """
        stat = self.sftp_client.stat(file_path)
        stat.st_ino = self._stat_st_ino(file_path)
        return stat

    def _getsize(self,file_path):
        """
        Emulation Definition - os.getsize
        """
        if self._exists(file_path):
            return self._stat(file_path).st_size
        return None

    def _stat_st_ino(self,file_path):
        """
        Emulation Definition - os.stat.st_ino
        Section 6 sub section 1 (Page 13)
        Inode is not incuded within the valid attribute flags for SSH2.
        https://filezilla-project.org/specs/draft-ietf-secsh-filexfer-07.txt
        """
        cmd = 'stat --printf="%i" {}'
        to_run = cmd.format(file_path)
        out = self.client.exec_command(to_run)
        stdout = int(out[1].read().decode())
        return stdout


    def _listdir(self,dir_path):
        """ 
        Emulation Definition - os.listdir
        """
        return self.sftp_client.listdir(dir_path)

    def _non_empty(self,file_path):
        if self._exists(file_path) and self._getsize(file_path):
            return True
        return False

    def _empty(self,file_path):
        return not self._non_empty(file_path)

    def _set_directory_and_file(self,file_path):
        self.directory, self.file_name = os.path.split(os.path.abspath(file_path))
        self.full_path = file_path
        if self._exists(file_path):
            self.file_stats = self._stat(file_path)
        else:
            self.missing = True
            

    def _set_offset_file(self,offset_file):
        if not offset_file:
            offset_file = os.path.join(self.directory,'{}.{}'.format(self.file_name,'offset'))
        self.offset_file = offset_file
        
    def _read_offset_file(self):
        if self._empty(self.offset_file):
            (self.offset_inode, self.offset) = [ 0,0 ]
            return
        offset_fh = self.sftp_client.open(self.offset_file,'r')
        ( self.offset_inode, self.offset ) = [ int(line.strip()) for line in offset_fh ]
        offset_fh.close()

    def _rotation_suspected(self):
        inode_change = self.offset_inode != self.file_stats.st_ino
        size_change = self._getsize(self.full_path) < self.offset
        if inode_change or size_change:
            return True
        
    def check_file(self,file_path,offset_file=None):
        
        self._set_directory_and_file(file_path)
        if self.missing:
            return None

        self._set_offset_file(offset_file)
        self._read_offset_file()

        if self._rotation_suspected():
            target_file = self._check_log_rotated()
            if target_file:
                self.sub_file = target_file
            else:
                # manual delete...
                #return None 
                pass

        self.buffer = io.StringIO()
        if self.sub_file:
            self.buffer.write(self._read_file(self.sub_file))
            self.offset = 0
        self.buffer.write(self._read_file(self.full_path))
        
        self._update_offset()
        self.buffer.seek(0)
        return self.buffer

    def _update_offset(self):
        offset_file = self.sftp_client.open(self.offset_file,'w')
        offset_file.write(str(self.file_stats.st_ino)+"\n")
        offset_file.write(str(self._getsize(self.full_path)))
        offset_file.close()

    def _read_file(self,file_path):
        fh = fileobj=self.sftp_client.open(file_path,'r')

        if file_path.endswith('.gz'):
            fh = gzip.GzipFile(fileobj=fh)

        fh.seek(self.offset)
        lines = fh.read().decode()
        fh.close()
        return lines

    def _check_log_rotated(self):
        rotated_file = self._find_log_rotated_matches()
        if rotated_file:
            if self._stat(rotated_file).st_ino == self.offset_inode:
                # pure rotation
                return rotated_file
            elif self._stat(self.full_path).st_ino == self.offset_inode:
                # copytruncate
                return rotated_file
            else:
                return None


    def _find_log_rotated_matches(self):
        
        # ROTATION SCHEME - NUMERIC
        # savelog(8)
        behavior = ['{}.0'.format(self.full_path),'{}.1.gz'.format(self.full_path) ]
        if ( self._exists(behavior[0]) and self._exists(behavior[1]) ):
            if ( self._stat(behavior[0]).st_mtime > self._stat(behavior[1]).st_mtime ):
                return behavior[0]

        # logrotate(8) - delay compress
        behavior = '{}.1'.format(self.full_path)
        if self._exists(behavior):
            return behavior

        # logrotate(8) - no delay compress
        behavior = '{}.1.gz'.format(self.full_path)
        if self._exists(behavior):
            return behavior


        # ROTATION SCHEME - DATE_TEXT
        possible_patterns = [
            # logrotate(8)
            "{}-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]",
            # logrotate(8)
            "{}-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].gz",
            # logrotate(8)
            "{}-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]",
            # logrotate(8)
            "{}-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].gz",
            # python.logging.handlers.TimedRotatingFileHandler
            "{}.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
        ]
        # custom rotation patterns added by user 
        if self.log_patterns:
            possible_patterns.extend(self.log_patterns)
        
        canidates = self._listdir(self.directory)
        for pattern in possible_patterns:
            matches = []
            regexp = pattern.format(self.file_name)
            for canidate in canidates:
                if re.match(regexp,canidate):
                    matches.append(canidate)
            if matches:
                matches.sort()
                return os.path.join(self.directory,matches[-1])
        return None
