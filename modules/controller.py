from modules.parsers import GenericParser, AptLogsParser, JournalLogParser, PackageVerificationParser, PackageUpgradeabilityParser
from definitions.constants import Constants
from multiprocessing import Pool
from modules.remotes import RemoteManager, Remote
from modules.services import ServiceManager
from modules.reports import ReportManager
from modules.local import CheckerManager, FileChecker

class Controller:

    def __init__(self, config):
        self.config = config
        self.scope = config.scope

        self.report_manager = ReportManager(self.config)

        self.parsers = []
        self._setup_scope()
        
    def _setup_scope(self):

        if 1 in self.scope:
            self.parsers += self._setup_log_parsers()
        if 2 in self.scope:
            self.parsers += self._setup_conf_parsers()
        if 3 in self.scope:
            self.parsers += self._setup_package_parser()
        if 4 in self.scope:
            self.service_manager = self._setup_service_manager()
        if 5 in self.scope:
            self.checker_manager = self._setup_checkers()
        if 6 in self.scope:
            self.remote_manager = self._setup_remote_manager()
        if 7 in self.scope:
            pass

    def _setup_log_parsers(self):
        parsers = []

        if self.config.distro == Constants.DISTRO.ARCHLINUX:            
            pacman_logs_path = self.config.get_value(Constants.SECTION.PACMAN_LOGS, 'Path')
            rules_path = self.config.get_value(Constants.SECTION.PACMAN_LOGS, 'RulesFile')   
            parsers.append(GenericParser(rules_path, Constants.SCOPE.LOG, pacman_logs_path))
        
        if self.config.distro == Constants.DISTRO.UBUNTU:
            apt_logs_path = self.config.get_value(Constants.SECTION.APT_LOGS, 'Path')
            rules_path = self.config.get_value(Constants.SECTION.APT_LOGS, 'RulesFile')     
            parsers.append(AptLogsParser(rules_path, Constants.SCOPE.LOG, apt_logs_path))

            dpkg_logs_path = self.config.get_value(Constants.SECTION.DPKG_LOGS, 'Path')
            rules_path = self.config.get_value(Constants.SECTION.DPKG_LOGS, 'RulesFile')
            parsers.append(GenericParser(rules_path, Constants.SCOPE.LOG, dpkg_logs_path))

        custom_definitions = self.config.get_custom_definitions()
        if custom_definitions is not None:
            for section in custom_definitions.sections():
                file_path = custom_definitions.get(section, 'Path')
                rules_path = custom_definitions.get(section, 'RulesFile')

                parsers.append(GenericParser(rules_path, Constants.SCOPE.LOG, file_path))

        #Journal
        if True:
            rules_path = f'{Constants.PATH.GENERIC_RULES_PATH}/{Constants.GENERIC.JOURNAL}.ini'
            parsers.append(JournalLogParser(rules_path, Constants.SCOPE.LOG))

        return parsers

    def _setup_conf_parsers(self):
        parsers = []

        # sshd_conf
        sshd_conf_path = self.config.get_value(Constants.SECTION.OPENSSH_CONF, 'Path')
        rules_path = self.config.get_value(Constants.SECTION.OPENSSH_CONF, 'RulesFile')     
        parsers.append(GenericParser(rules_path, Constants.SCOPE.CONF, sshd_conf_path))

        # passwd file
        passwd_path = self.config.get_value(Constants.SECTION.PASSWD, 'Path')
        rules_path = self.config.get_value(Constants.SECTION.PASSWD, 'RulesFile')     
        parsers.append(GenericParser(rules_path, Constants.SCOPE.CONF, passwd_path))

        # apache conf
        apache_conf_path = self.config.get_value(Constants.SECTION.APACHE_CONF, 'Path')
        rules_path = self.config.get_value(Constants.SECTION.APACHE_CONF, 'RulesFile')     
        parsers.append(GenericParser(rules_path, Constants.SCOPE.CONF, apache_conf_path))

        # login_defs conf
        login_defs_conf_path = self.config.get_value(Constants.SECTION.LOGIN_DEFS, 'Path')
        rules_path = self.config.get_value(Constants.SECTION.LOGIN_DEFS, 'RulesFile')     
        parsers.append(GenericParser(rules_path, Constants.SCOPE.CONF, login_defs_conf_path))

        return parsers

    def _setup_package_parser(self):
        parsers = []

        if self.config.distro == Constants.DISTRO.ARCHLINUX:            
            verify_command = self.config.get_value(Constants.SECTION.PACMAN_CHECKS, 'Command')
            upgradeable_command = self.config.get_value(Constants.SECTION.UPGRADEABLE, 'Command')
            verify_rules_path = self.config.get_value(Constants.SECTION.PACMAN_CHECKS, 'RulesFile')
            upgradeable_rules_path = self.config.get_value(Constants.SECTION.UPGRADEABLE, 'RulesFile')   
        
        if self.config.distro == Constants.DISTRO.UBUNTU:
            verify_command = self.config.get_value(Constants.SECTION.DPKG_CHECKS, 'Command')
            upgradeable_command = self.config.get_value(Constants.SECTION.UPGRADEABLE, 'Command')
            verify_rules_path = self.config.get_value(Constants.SECTION.DPKG_CHECKS, 'RulesFile')     
            upgradeable_rules_path = self.config.get_value(Constants.SECTION.UPGRADEABLE, 'RulesFile')     
        
        verifier_parser = PackageVerificationParser(verify_rules_path, Constants.SCOPE.PACKAGE, verify_command)
        upgradeable_parser = PackageUpgradeabilityParser(upgradeable_rules_path, Constants.SCOPE.PACKAGE, upgradeable_command, self.config.distro)

        parsers.append(verifier_parser)
        parsers.append(upgradeable_parser)

        return parsers

    def _setup_service_manager(self):
        service_manager = ServiceManager(self.config)
        return service_manager

    def _setup_checkers(self):
        checker_manager = CheckerManager(self.config)
        return checker_manager

    def _setup_remote_manager(self):
        remote_manager = RemoteManager(Constants.PATH.REMOTES_PATH, self.config)
        return remote_manager

    def execute_scope(self):
        if 1 in self.scope or 2 in self.scope or 3 in self.scope:
            self._execute_parsers()

        if 4 in self.scope:
            self._process_services()

        if 5 in self.scope:
            self._process_checkers()

        if 6 in self.scope:
            self._process_remotes()

    def _execute_parsers(self):
        pool = Pool()
        tasks = []

        for parser in self.parsers:
            if parser.isParallelizable:
                tasks.append((pool.apply_async(parser.parse), parser.scope))
            else:
                result = parser.parse()
                self._generate_report(result, parser.scope)
        
        for process, scope in tasks:
            result = process.get()
            self._generate_report(result, scope)
    
    def _process_remotes(self):

        pool = Pool()
        processes = []
        
        for remote in self.remote_manager.remotes:
            processes.append(pool.apply_async(remote.analyze))
            
        for process in processes:
            result = process.get()
            self._generate_report(result, Constants.SCOPE.REMOTE)

    def _process_services(self):
        pool = Pool()
        processes = []
        results = []

        for service in self.service_manager.services:
            processes.append(pool.apply_async(service.analyze))
            
        for process in processes:
            result = process.get()
            if result:
                results.append(result)

        self._generate_report(results, Constants.SCOPE.SERVICE)

    def _process_checkers(self):
        pool = Pool()
        processes = []

        for checker in self.checker_manager.checkers:
            if checker.isParallelizable:
                processes.append(pool.apply_async(checker.analyze))
            else:
                result = checker.analyze()
                self._generate_report(result, Constants.SCOPE.LOCAL)
        
        for process in processes:
            result = process.get()

            self._generate_report(result, Constants.SCOPE.LOCAL)

    def _generate_report(self, input, scope):
        self.report_manager.generate_report(input, scope)

    def save_reports(self):
        for scope in self.scope:
            self.report_manager.save_report(scope)

