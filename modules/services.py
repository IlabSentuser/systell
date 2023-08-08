from definitions.constants import Constants
import subprocess
import re

class Service:
    def __init__(self, name, state, preset):
        self.name = name
        self.state = state
        self.preset = preset

    def analyze(self):
        result = {'Service': self.name}
        
        exposure = None
        different_than_preset = None

        security_command = f'{Constants.COMMAND.SYSTEMD_SECURITY} {self.name}'
        verification_command = f'{Constants.COMMAND.SYSTEMD_VERIFY} {self.name}'

        security_output = subprocess.run(security_command, shell=True, capture_output=True, text=True)
        verification_output = subprocess.run(verification_command, shell=True, capture_output=True, text=True)

        if security_output.returncode == 0:
            exposure = security_output.stdout.split('\n')[-2]
            exposure = exposure.split(':')[-1].split(' ')[1:3]

        if exposure:
            result['Exposure'] = exposure[0]
            result['Risk'] = exposure[1]

        result['SyntaxErrors'] = verification_output.returncode
 
        if self.state != self.preset:
            different_than_preset = (self.state, self.preset)

        if different_than_preset:
            result['PresetDivergence'] = different_than_preset

        return result

class FailedService:
    def __init__(self, name, load, active, sub, description):
        self.name = name
        self.load = load
        self.active = active
        self.sub = sub
        self.description = description

    def analyze(self):
        result = {'Failed service': self.name}

        result['Load'] = self.load
        result['Active'] = self.active
        result['Sub'] = self.sub
        result['Description'] = self.description

        return result

class ServiceManager:
    def __init__(self, config):
        self.config = config
        self.services = self.get_services()
        self.services += self.get_failed_services()

    def get_services(self):
        command = Constants.COMMAND.SYSTEMD_UNITS
        services = []

        output = subprocess.run(command, shell=True, capture_output=True, text=True)
        for entry in output.stdout.split('\n'):
            match = re.search(Constants.REGEX.SYSTEMD_UNITS_STATUS, entry)

            if match:
                if match[3] in ('enabled', 'disabled'):
                    services.append(Service(match[1], match[2], match[3]))
        
        return services

    def get_failed_services(self):
        command = Constants.COMMAND.SYSTEMD_FAILED
        services = []

        output = subprocess.run(command, shell=True, capture_output=True, text=True)
    
        for entry in output.stdout.split('\n')[1:-6]:
            match = re.search(Constants.REGEX.SYSTEMD_FAILED_UNITS, entry)

            if match:
                services.append(FailedService(match[1], match[2], match[3], match[4], match[5]))
            
        return services
