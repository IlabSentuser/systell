from definitions.constants import Constants
import hashlib
import os
import pwd
import grp
import socket
try:
    import psutil
except ImportError:
    print('psutil module not available, please make sure to install it.')

class CheckerManager:
    
    def __init__(self, config):
        self.config = config
        self.checkers = self._setup_checkers()

    def _setup_checkers(self):
        checkers = []

        checkers.append(FileChecker())
        checkers.append(PortChecker())
        checkers.append(ProcessesChecker())

        return checkers

class Checker:
    __pretty_name__ = 'Generic Checker'
    isParallelizable = True

    def _load_database(self, database_file):
        with open(database_file) as database_file:
            database_entries = []

            for line in database_file:
                if not line.startswith('#') and not line.startswith('\n'):                    
                    line = line.rstrip()

                    entry = {}
                    key = ''
                    value = ''
                    current_token = ''
                    in_quotes = False

                    for char in line:
                        if char == '"':
                            if in_quotes:
                                in_quotes = False
                            else:
                                in_quotes = True
                                continue

                        if (char != '=' and char != ' ' and char != '"') or in_quotes:
                            current_token += char
                        
                        if (char == '=' or char == ' ' or char == '"') and not in_quotes:
                            if char == '=':
                                key = current_token
                            elif char == ' ' or char == '"':
                                value = current_token
                            
                            current_token = ''
                        
                        if len(key) > 0 and len(value) > 0:
                                entry[key] = value
                                key = ''
                                value = ''

                    if len(value) == 0 and len(current_token) > 0:
                        entry[key] = current_token
                        key = ''
                        value = ''

                    database_entries.append(entry)

            self.database = database_entries

    def _generate_header(self, collection, total_entries):
        matched_entries = str(len(collection))

        return f'#Checker: {self.__pretty_name__} #Total entries: {total_entries} #Incorrect entries: {matched_entries}'

class FileChecker(Checker):
    __pretty_name__ = 'File Checker'
    
    def __init__(self):
        database_file = Constants.PATH.DATABASE.FILESYSTEM
        self._load_database(database_file)

    def analyze(self):
        block_size = 4096
        total_entries = len(self.database)
        results = []

        for entry in self.database:
            checksum = entry.get('md5', None)
            file_path = entry.get('path', None)
            perms = entry.get('perms', None)
            owner = entry.get('owner', None)
            group = entry.get('group', None)
            result = {}

            if checksum is not None:
                md5hash = hashlib.md5()

                try:
                    with open(file_path, 'rb') as file:
                        while block := file.read(block_size):
                            md5hash.update(block)
                
                    if md5hash.hexdigest() != checksum:
                        result['MD5 check'] = Constants.CHECK_STATUS.INCORRECT
                except FileNotFoundError:
                    result['MD5 check'] = Constants.CHECK_STATUS.INCORRECT

            try:
                stats = os.stat(file_path)
            except FileNotFoundError:
                result['Permisions check'] = Constants.CHECK_STATUS.INCORRECT
                result['Owner check'] = Constants.CHECK_STATUS.INCORRECT
                result['Group check'] = Constants.CHECK_STATUS.INCORRECT

            if perms is not None:
                file_perms = oct(stats.st_mode)[-3:]
                if file_perms != perms:
                    result['Permisions check'] = Constants.CHECK_STATUS.INCORRECT
            
            if owner is not None:
                file_owner = pwd.getpwuid(stats.st_uid).pw_name
                if file_owner != owner:
                    result['Owner check'] = Constants.CHECK_STATUS.INCORRECT

            if group is not None:
                file_group = grp.getgrgid(stats.st_gid).gr_name
                if file_group != group:
                    result['Group check'] = Constants.CHECK_STATUS.INCORRECT

            if len(result) > 0:
                result['File'] = file_path
                results.append(result)

        if len(results) > 0:
            results = [self._generate_header(results, total_entries)] + results
        else:
            results = [self._generate_header(results, total_entries)]
          
        return results

class PortChecker(Checker):
    __pretty_name__ = 'Port Checker'

    def analyze(self):
        open_ports = []

        for connection in psutil.net_connections(kind='inet'):
            if connection.status == psutil.CONN_LISTEN:
                entry = {
                    'Port': connection.laddr.port,
                    'PID': connection.pid,
                    'Process': psutil.Process(connection.pid).name(),
                    'Protocol': 'TCP' if connection.type == socket.SOCK_STREAM else 'UDP'
                }
                open_ports.append(entry)
        
        if len(open_ports):
            return [self._generate_header(open_ports)] + open_ports
        else:
            return [self._generate_header(open_ports)]
        
    def _generate_header(self, collection):
        open_ports_count = len(collection)

        return f'#Checker: {self.__pretty_name__} #Open ports: {open_ports_count}'

class ProcessesChecker(Checker):
    __pretty_name__ = 'Processes Checker'
    isParallelizable = False
    
    def __init__(self):
        database_file = Constants.PATH.DATABASE.PROCESSES
        self._load_database(database_file)

        self._setup_lists()
        self.running_processes = self.get_running_processes()

    def _setup_lists(self):
        white_list = []
        black_list = []

        for entry in self.database:

            acl = entry.get('acl', None)
            pid = entry.get('pid', None)
            username  = entry.get('username', None)
            name = entry.get('name', None)
            cmd = entry.get('cmdline', None)

            rule = {key:value for key, value in entry.items() if key != 'acl'}

            if acl == 'whitelist':
                white_list.append(rule)
            elif acl == 'blacklist':
                black_list.append(rule)
        
        self.white_list = white_list
        self.black_list = black_list

    def get_running_processes(self):
        processes = []
         
        for process in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            processes.append(process)
        
        return processes
    
    def analyze(self):
        blacklisted_processes = []
        whitelisted_processes = []

        for process in self.running_processes:

            in_blacklist = self._check_process_in_list(process, self.black_list)
            in_whitelist = self._check_process_in_list(process, self.white_list)

            if in_blacklist is not None:
                in_blacklist['acl'] = 'blacklist'
                blacklisted_processes.append(in_blacklist)
            
            if in_whitelist is not None:
                in_whitelist['acl'] = 'whitelist'
                whitelisted_processes.append(in_whitelist)
            


        results = [self._generate_header(whitelisted_processes, blacklisted_processes)]

        if len(whitelisted_processes) > 0:
             results += whitelisted_processes
        
        if len(blacklisted_processes) > 0:
            results += blacklisted_processes

        return results

    def _check_process_in_list(self, process, checklist):
        for entry in checklist:
            matches = 0
            for key, value in entry.items():
                if key == 'cmdline':
                    process_info = ' '.join(process.info['cmdline'])
                else:
                    process_info = process.info[key]

                if process_info == value:
                    matches += 1
            if matches == len(entry):
                result = {'acl':''}
                for key, value in process.info.items():
                    if key == 'cmdline':
                        cmdline = ' '.join(process.info['cmdline'])
                        result[key] = cmdline
                    else:
                        result[key] = value

                return result
            
        return None

    def _generate_header(self, whitelist, blacklist):
        whitelist_length = len(whitelist)
        blacklist_length = len(blacklist)

        total_entries = len(self.running_processes)

        return f'#Checker: {self.__pretty_name__} #Running processes: {total_entries} #Processes in whitelist: {whitelist_length} #Processes in blacklist: {blacklist_length}'
        