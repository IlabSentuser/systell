from definitions.constants import Constants 
import configparser
import nmap

class Remote:
    def __init__(self, id, ip, port, operation, assessment=None):
        self.id = id
        self.ip = ip.replace(' ','').split(',')
        self.port = port.replace(' ','').split(',')
        
        self.operation = operation

        if assessment is not None:
            self.assessment = {}
            assessments = assessment.split(',')

            for entry in assessments:
                tmp = entry.split(':')
                self.assessment[tmp[0]] = tmp[1]
        else:
            self.assessment = None

    def analyze(self):
        if self.operation == Constants.SCAN_OPERATION.SCAN:
            return self._generate_report(self.scan())
        else:
            return self._generate_report(self.assess())
    
    def _scan(self, ports=None):
        scanner = nmap.PortScanner()
        targets = ' '.join(self.ip)
        if ports is None:
            ports = ','.join(self.port)

        scanner.scan(hosts=targets, arguments='-Pn -sV -O', sudo=True, ports=ports)

        return scanner

    def scan(self):
        results = []

        scanner = self._scan()
        scan_results = scanner.all_hosts()

        for host in scan_results:
            ports_summary = []
            for port in scanner[host].all_tcp():
                ports_summary.append((port, scanner[host].tcp(port)['state']))

            result = (host, scanner[host].state(), ports_summary)
            results.append(result)

        return results

    def assess(self):

        results = []

        other_ports = self.assessment.get(Constants.ASSESSMENT.OTHER_PORTS)
        os = self.assessment.get(Constants.ASSESSMENT.OS)
        ports = None

        if other_ports is not None:
            ports = '1-65535' 

        scanner = self._scan(ports)
        scan_results = scanner.all_hosts()

        for host in scan_results:
            if os is not None:
                if len(scanner[host]["osmatch"]) and os in scanner[host]["osmatch"][0]["name"]:
                    result = (host, Constants.ASSESSMENT.OS, Constants.CHECK_STATUS.CORRECT)
                else:
                    result = (host, Constants.ASSESSMENT.OS, Constants.CHECK_STATUS.INCORRECT)
                
                results.append(result)

            for key, value in self.assessment.items():
                if key != Constants.ASSESSMENT.OS and key != Constants.ASSESSMENT.OTHER_PORTS:
                    try:
                        port_status = scanner[host].tcp(int(key))['state']
                    except KeyError:
                        port_status = Constants.PORT_STATUS.CLOSED

                    if port_status == value:
                        result = (host, key, Constants.CHECK_STATUS.CORRECT)
                    else:
                        result = (host, key, Constants.CHECK_STATUS.INCORRECT)
                    
                    results.append(result)

            if other_ports is not None:
                result = None
                for port in range(1,65535):
                    try:
                        port_status = scanner[host].tcp(port)['state']
                    except KeyError:
                        port_status = Constants.PORT_STATUS.CLOSED

                    if port_status != other_ports and str(port) not in self.assessment.keys():
                        result = (host, Constants.ASSESSMENT.OTHER_PORTS, Constants.CHECK_STATUS.INCORRECT, port)
                        break
                
                if result is None:
                    result = (host, Constants.ASSESSMENT.OTHER_PORTS, Constants.CHECK_STATUS.CORRECT)

                results.append(result)

        return results

    # This method exists in order to support a future functionality, it is currently not used
    def _get_all_ips(self):
        ips = []

        for ip in self.ip:
            octets = ip.split('.')
            if '-' in octets[0]:
                start1, end1 = octets[0].split('-')
            else:
                start1 = end1 = octets[0]
            if '-' in octets[1]:
                start2, end2 = octets[1].split('-')
            else:
                start2 = end2 = octets[1]
            if '-' in octets[2]:
                start3, end3 = octets[2].split('-')
            else:
                start3 = end3 = octets[2]
            if '-' in octets[3]:
                start4, end4 = octets[3].split('-')
            else:
                start4 = end4 = octets[3]

            for i in range(int(start1), int(end1) + 1):
                for j in range(int(start2), int(end2) + 1):
                    for k in range(int(start3), int(end3) + 1):
                        for l in range(int(start4), int(end4) + 1):
                            ips.append(f'{i}.{j}.{k}.{l}')
        
        return ips

    def _generate_report(self, results):
        report = []

        header = f'Remote: {self.id}'
        report.append(header)

        if len(results) > 0:
            previous_host = ''

            for result in results:
                host = f' Host: {result[0]}'
                if result[1] == Constants.HOST_STATUS.DOWN:
                    status = f'  Status: {result[1]}'
                    report.append(host)
                    report.append(status)
                else:
                    if self.operation == Constants.SCAN_OPERATION.SCAN:
                        status = f'  Status: {result[1]}'
                        summary_header = f'  Port summary:'

                        report.append(host)
                        report.append(status)
                        report.append(summary_header)
                        indentation = len(summary_header)

                        for port in result[2]:
                            report.append(f'{" "* indentation}{port[0]}: {port[1]}')                  
                    elif self.operation == Constants.SCAN_OPERATION.ASSESS:

                        if previous_host != host:
                            report.append(host)
                            previous_host = host                    

                        if result[1] == Constants.ASSESSMENT.OS:
                            os = f'  {Constants.ASSESSMENT.OS} is {self.assessment.get(Constants.ASSESSMENT.OS)}: {result[2]}'
                            report.append(os)
                        elif result[1] == Constants.ASSESSMENT.OTHER_PORTS:
                            other_ports = f'  {Constants.ASSESSMENT.OTHER_PORTS} are {self.assessment.get(Constants.ASSESSMENT.OTHER_PORTS)}: {result[2]}'
                            if len(result) == 4:
                                indentation = len (other_ports)
                                reason = f'{" " * indentation}Reason: at least one port does not satisfy the condition ({result[3]})'
                            report.append(other_ports)
                            report.append(reason)
                        else:
                            assessment = f'  Port {result[1]} is {self.assessment.get(result[1])}: {result[2]}'
                            report.append(assessment)
        else:
            report.append(f' No host connection succeded')

        return report
 
class RemoteManager:

    def __init__(self, remotes_path, config):
        self.remotes_path = remotes_path
        self.config = config
        
        self._setup_remotes()

    def _setup_remotes(self):
        remotes_file = configparser.ConfigParser()
        remotes_file.read(self.remotes_path)

        remotes = []

        for section in remotes_file.sections():
            id = section
            ip = remotes_file.get(section, Constants.REMOTE.IP)
            port = remotes_file.get(section, Constants.REMOTE.PORT)
            operation = remotes_file.get(section, Constants.REMOTE.OPERATION)
            assessment = remotes_file.get(section, Constants.REMOTE.ASSESSMENT, fallback=None)
            
            remote = Remote(id, ip, port, operation, assessment=assessment)
            remotes.append(remote)

        self.remotes = remotes
