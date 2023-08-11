class Constants:

        class ERROR:
            CONNECTION_ERROR = 'CONNECTION_ERROR'

        DATABASE_ENTRY = ['md5', 'perms', 'path', 'owner', 'group', 'acl', 'cmd']

        class SCOPE:
            LOG = 1
            CONF = 2
            PACKAGE = 3
            SERVICE = 4
            LOCAL = 5
            REMOTE = 6
            SMART = 7
            def get_scopes():
                # smart scope removed as not fully implemented
                # return 'LOG=1 CONF=2 PACKAGE=3 SERVICE=4 LOCAL=5 REMOTE=6 SMART=7'
                return 'LOG=1 CONF=2 PACKAGE=3 SERVICE=4 LOCAL=5 REMOTE=6'
            
            def get_scope_name(scope):
                scope_names = {1:'LOG', 2:'CONF', 3:'PACKAGE', 4:'SERVICE', 5:'LOCAL', 6:'REMOTE', 7:'SMART'}

                return scope_names[scope]
            
            def get_scope_index(scope):
                scope_index = {'LOG': 1, 'CONF': 2, 'PACKAGE': 3, 'SERVICE': 4, 'LOCAL': 5, 'REMOTE': 6, 'SMART': 7}

                return scope_index[scope]

        class DISTRO:
            UBUNTU = 'Ubuntu'
            ARCHLINUX = 'Arch Linux'

        class PATH:
            UBUNTU_LOCATIONS_PATH = 'definitions/locations/ubuntu.ini'
            ARCHLINUX_LOCATIONS_PATH = 'definitions/locations/archlinux.ini'
            CUSTOM_DEFINITIONS_PATH = 'definitions/locations/custom.ini'
            RULES_PATH = 'definitions/rules'
            GENERIC_RULES_PATH = 'definitions/rules/generic'
            REMOTES_PATH = 'definitions/remotes.ini'
            DEFAULT_REPORTS_PATH = '/tmp'
            DEFAULT_CONF_PATH = 'definitions/'

            class DATABASE:
                FILESYSTEM = 'definitions/databases/filesystem.list'
                PROCESSES = 'definitions/databases/processes.list'

        class SECTION:
            TYPE_LINE = 'LINE'
            TYPE_BLOCK = 'BLOCK'
            NETWORK_MANAGER_CONF = 'NetworkManager_conf'
            APACHE_CONF = 'Apache_conf'
            APACHE_LOGS = 'Apache_logs'
            OPENSSH_CONF = 'OpenSSH_conf'
            MYSQL_CONF = 'MySQL_conf'
            SYSTEMD_CONF = 'systemd_conf'
            APT_CONF = 'apt_conf'
            APT_LOGS = 'apt_logs'
            DPKG_LOGS = 'dpkg_logs'
            PACMAN_CONF = 'pacman_conf'
            PACMAN_LOGS = 'pacman_logs'
            PACMAN_CHECKS = 'pacman_checks'
            DPKG_CHECKS = 'dpkg_checks'
            UPGRADEABLE = 'upgradeable' 
            PASSWD = 'passwd'
            LOGIN_DEFS = 'login_defs'

        class GENERIC:
            JOURNAL = 'journal'
        
        class COMMAND:
            SYSTEMD_UNITS = 'sudo systemctl list-unit-files --type=service'
            SYSTEMD_FAILED = 'systemctl list-units --type=service --state=failed'
            SYSTEMD_VERIFY = 'sudo systemd-analyze verify'
            SYSTEMD_SECURITY = 'sudo systemd-analyze security'

        class REGEX:
            SYSTEMD_UNITS_STATUS = '^(?P<UnitFile>.*?)[ ]+(?P<State>\w+)[ ]+(?P<Preset>[a-z-]+)'
            SYSTEMD_FAILED_UNITS = '.*? (?P<Unit>.+?) (?P<Load>.+?) (?P<Active>.+?) (?P<Sub>.+?) (?P<Description>.+)'

        class RULE_FIELD:
            LEVEL = 'Level'
            TYPE = 'Type'
            SINCE = 'Since'
            UNTIL = 'Until'
            FILTERS = 'Filters'
            REGEX = 'Regex'

        class RULE_TYPE:
            REGEX = 'Regex'
            FILTERED = 'Filtered'
            COMBINED = 'Combined'

        class REMOTE:
            IP = 'IP'
            PORT = 'Port'
            OPERATION = 'Operation'
            ASSESSMENT = 'Assessment'

        class ASSESSMENT:
            OS = 'OS'
            OTHER_PORTS = 'OTHER_PORTS'

        class SCAN_OPERATION:
            ASSESS = 'assess'
            SCAN = 'scan'

        class FIREWALL_STATUS:
            PRESENT = 'Present'
            UNKNOWN = 'Unknown'
            LIKELY = 'Likely'
            NOT_PRESENT = 'Not present'
        
        class PORT_STATUS:
            OPEN = 'open'
            UNKNOWN = 'unknown'
            CLOSED = 'closed'
            FILTERED = 'filtered'
            OPEN_FILTERED = 'open or filtered'
        
        class HOST_STATUS:
            UP = 'Up'
            DOWN = 'Down'

        class CHECK_STATUS:
            CORRECT = 'Correct'
            INCORRECT = 'Incorrect'
            ERROR = 'Error'

        class SYSTEMD_UNIT_STATE:
            ENABLED = 'enabled'
            ENABLED_RUNTIME = 'enabled-runtime'
            LINKED = 'linked'
            LINKED_RUNTIME = 'linked-runtime'
            ALIAS = 'alias'
            MASKED = 'masked'
            MASKED_RUNTIME = 'masked-runtime'
            STATIC = 'static'
            INDIRECT = 'indirect'
            DISABLED = 'disabled'
            GENERATED = 'generated'
            TRANSIENT = 'transient'
            BAD = 'bad'
            NOT_FOUND = 'not-found'

