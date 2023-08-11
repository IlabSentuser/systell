from modules.parsers import GenericParser, GenericBlockParser, JournalLogParser, GenericCommandParser
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
        self.definitions = []
        self._setup_scope()
        
    def _setup_scope(self):
        if Constants.SCOPE.LOG in self.config.scope or Constants.SCOPE.CONF in self.config.scope or Constants.SCOPE.PACKAGE in self.config.scope:
            for section in self.config.locations_config.sections():
                section_scope = self.config.get_value(section, 'Scope')
                section_scope = Constants.SCOPE.get_scope_index(section_scope)

                if section_scope in self.scope:
                    self._setup_parser(section, section_scope)
                    
        # Add the journal to the parsers list if it was enabled.
        if Constants.SCOPE.LOG in self.scope and self.config.use_journal == True:
            rules_path = f'{Constants.PATH.GENERIC_RULES_PATH}/{Constants.GENERIC.JOURNAL}.ini'
            parser = JournalLogParser(rules_path, Constants.SCOPE.LOG)
            self.parsers.append(parser)
        
        if Constants.SCOPE.SERVICE in self.scope:
            self.service_manager = self._setup_service_manager()
        if Constants.SCOPE.LOCAL in self.scope:
            self.checker_manager = self._setup_checkers()
        if Constants.SCOPE.REMOTE in self.scope:
            self.remote_manager = self._setup_remote_manager()
        if Constants.SCOPE.SMART in self.scope:
            # Smart module is coming in a future version
            pass

    def _setup_parser(self, section, scope):
        path = self.config.get_value(section, 'Path')
        command = self.config.get_value(section, 'Command')

        if path is not None:
            rules_path = self.config.get_value(section, 'RulesFile')
            parser_type = self.config.get_value(section, 'Type')
            is_command = False
        
        if command is not None:
            rules_path = self.config.get_value(section, 'RulesFile')
            parser_type = self.config.get_value(section, 'Type')
            is_command = True
        
        if not is_command:
            if parser_type is None or parser_type == Constants.SECTION.TYPE_LINE:
                parser = GenericParser(rules_path, scope, path)
            elif parser_type == Constants.SECTION.TYPE_BLOCK:
                start_delimiter = self.config.get_value(section, 'StartDelimiter')
                end_delimiter = self.config.get_value(section,'EndDelimiter')

                parser = GenericBlockParser(rules_path, scope, start_delimiter, end_delimiter, path)
        else:
            parser = GenericCommandParser(rules_path, scope, command)

        self.parsers.append(parser)

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

