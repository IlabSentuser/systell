import configparser
from definitions.constants import Constants 
from entities import Rule
import re
from systemd import journal
from datetime import datetime
from utils import time_parser
import subprocess

# This parser essentially gets information from a source (file) and for each line it parses its result agains each of the rules
class GenericParser:
    __pretty_name__ = 'Generic Parser'
    isParallelizable = True

    def __init__(self, rules_path, scope, source = None):
        self.rules_path = rules_path
        self.scope = scope

        if source:
            self.source = source

        #Load and initialize rules
        self.load_rules()

    def load_rules(self):
        rules_file = configparser.ConfigParser()
        rules_file.read(self.rules_path)

        rule_list = []

        for section in rules_file.sections():
            id = section
            rule_type = rules_file.get(section, Constants.RULE_FIELD.TYPE)
            since = rules_file.get(section, Constants.RULE_FIELD.SINCE, fallback=None)
            until = rules_file.get(section, Constants.RULE_FIELD.UNTIL, fallback=None)
            filters = rules_file.get(section, Constants.RULE_FIELD.FILTERS, fallback=None)
            regex = rules_file.get(section, Constants.RULE_FIELD.REGEX, fallback=None)
            rule = Rule(id, rule_type, since, until, filters, regex)
            rule_list.append(rule)
        self.rules = rule_list

    def parse(self):
        output = []
        total_entries = 0

        with open(self.source, 'r') as file:
            for line in file:
                total_entries += 1 
                
                result = self._parse_entry(line)
                if result:
                    for item in result:
                        output.append(item)
        
        if len(output) > 0:
            output = [self._generate_header(output, total_entries)] + output
        else:
            output = [self._generate_header(output, total_entries)]
            
        return output
    
    def _generate_header(self, collection, total_entries):
        matched_entries = str(len(collection))
        rule_count = str(len(self.rules))

        return f'#Parser: {self.__pretty_name__} #Total entries: {total_entries} #Matched entries: {matched_entries} #Rule count: {rule_count} Resource: {self.source.split("/")[-1]}'

    def _parse_entry(self, entry):
        output = []

        for rule in self.rules:
            match = None

            if rule.rule_type == Constants.RULE_TYPE.REGEX:
                match = re.search(rule.regex, entry)
            elif rule.rule_type == Constants.RULE_TYPE.FILTERED:
                if all(filter in entry for filter in rule.filters):
                    #If not done what follows, when using the rule id on the regex it will fail if the rule id contains the spaces, hence we remove them
                    id_without_spaces = rule.id.replace(' ', '')
                    match = re.search('(?P<' + id_without_spaces + '>.*)', entry)
            else:
                if all(filter in entry for filter in rule.filters):
                    match = re.search(rule.regex, entry)

            if match and isinstance(match, re.Match):
                output.append(rule.id + ' ==> ' + str(match.groupdict()))
            elif match:
                output.append(rule.id + ' ==> ' +str(match))

        return output

    def set_pretty_name(self, name):
        self.__pretty_name__ = name

class AptLogsParser(GenericParser):
    __pretty_name__ = 'Aptitude Logs Parser'

    def parse(self):
        output = []
        block_started = False
        block = []
        total_entries = 0

        with open(self.source, 'r') as file:            
            for line in file:
                total_entries += 1 
                
                if line.startswith('Start-Date:'):
                    block_started = True
                elif line.startswith('End-Date:'):
                    block.append(line)
                    block_started = False
                
                if block_started:
                    block.append(line)
                else:
                    if len(block) > 0:
                        line = ' '.join(block).replace('\n', '')
                        block = []
                        
                        result = self._parse_entry(line)
                        if result:
                            for item in result:
                                output.append(item)
                                
        if len(output) > 0:
            output = [self._generate_header(output, total_entries)] + output
        else:
            output = [self._generate_header(output, total_entries)]
            
        return output

# This parser is very different to the GenericParserInterface. Key points on this class are: it creates a reader for each rule and then configures the reader according to the rule information (Until, Since, Filters, etc), then for each reader it parses each entry against the rule associated with the reader.
class JournalLogParser(GenericParser):
    __pretty_name__ = 'Journal Logs Parser'
    isParallelizable = False

    def __init__(self, rules_path, scope):
        super().__init__(rules_path, scope, 'journal')
        
    def load_rules(self):
        super().load_rules()
        self._setup_readers()

    def _setup_readers(self):
        self.readers = []
        for rule in self.rules:
            reader = journal.Reader()
            if rule.rule_type != Constants.RULE_TYPE.REGEX:
                if len(rule.filters) > 0:
                    for filter in rule.filters:
                        reader.add_match(filter)
                else:
                    #If no filter was specified, watch all priorities
                    reader.add_match('PRIORITY=0')
                    reader.add_match('PRIORITY=1')
                    reader.add_match('PRIORITY=2')
                    reader.add_match('PRIORITY=3')
                    reader.add_match('PRIORITY=4')
                    reader.add_match('PRIORITY=5')
                    reader.add_match('PRIORITY=6')
                    reader.add_match('PRIORITY=7')

            if rule.since and rule.since[0] == '-':
                time = time_parser(rule.since)
                reader.seek_realtime(datetime.now() - time)
            elif rule.since:
                reader.seek_realtime(datetime.strptime(rule.since, '%Y-%m-%d %H:%M:%S'))
            else:
                #If no since option was specified, default to 1 hour
                reader.seek_realtime(datetime.now() - timedelta(hours=1))

            #To associate each reader with its corresponding rule.
            reader.rule = rule

            self.readers.append(reader)

    def parse(self):
        output = []

        total_entries = 0

        for reader in self.readers:    
            for entry in reader:
                total_entries += 1

                result = self._parse_entry(entry, reader.rule)
                if result:
                    for item in result:
                        output.append(item)

        if len(output) > 0:
            output = [self._generate_header(output, total_entries)] + output
        else:
            output = [self._generate_header(output, total_entries)]

        return output
    
    def _parse_entry(self, entry, rule):
        output = []
        match = None

        if rule.until:
            timezone = entry['__REALTIME_TIMESTAMP'].tzinfo
            
            if rule.until[0] == '-':
                time = time_parser(rule.until)
                time = datetime.now(timezone) - time
            elif rule.until == 'NOW':
                time = None
            else:
                time = datetime.strptime(rule.until, '%Y-%m-%d %H:%M:%S')
        
        #If a time to define until when to filter exists, and an entry is found that exceeds this time, then skip this rule
        if time and entry['__REALTIME_TIMESTAMP'] > time:
            return output

        if rule.rule_type == Constants.RULE_TYPE.REGEX:
            match = re.search(rule.regex, str(entry))
        elif rule.rule_type == Constants.RULE_TYPE.FILTERED:
            #If not done what follows, when using the rule id on the regex it will fail if the rule id contains the spaces, hence we remove them
            id_without_spaces = rule.id.replace(' ', '')
            match = re.search('(?P<' + id_without_spaces + '>.*)', entry['MESSAGE'])
        else:
            match = re.search(rule.regex, entry['MESSAGE'])

        if match and isinstance(match, re.Match):
            output.append(rule.id + ' ==> ' + str(match.groupdict()))
        elif match:
            output.append(rule.id + ' ==> ' +str(match))
        
        return output

class PackageVerificationParser(GenericParser):
    __pretty_name__ = 'Package Verification Parser'
    isParallelizable = True

    def parse(self):
        output = []

        checks = self._get_checks()
        total_entries = len(checks)

        for line in checks:
            result = self._parse_entry(line)
            if result:
                for item in result:
                    output.append(item)
        
        if len(output) > 0:
            output = [self._generate_header(output, total_entries)] + output
        else:
            output = [self._generate_header(output, total_entries)]
            
        return output

    def _get_checks(self):
        command_output = subprocess.run(self.source, shell=True, capture_output=True, text=True)

        output = command_output.stdout.split('\n')[0:-1] + command_output.stderr.split('\n')[0:-1]

        return output

class PackageUpgradeabilityParser(PackageVerificationParser):
    __pretty_name__ = 'Package Upgradability Parser'

    def __init__(self, rules_path, scope, source = None, distro = Constants.DISTRO.ARCHLINUX):
        super().__init__(rules_path, scope, source)
        self.distro = distro

    def parse(self):
        output = []

        checks = self._get_checks()

        if self.distro == Constants.DISTRO.ARCHLINUX:
            total_entries = len(checks)
        else:
            total_entries = len(checks) - 1

        for line in checks:
            result = self._parse_entry(line)
            if result:
                for item in result:
                    output.append(item)
        
        if len(output) > 0:
            output = [self._generate_header(output, total_entries)] + output
        else:
            output = [self._generate_header(output, total_entries)]
            
        return output
