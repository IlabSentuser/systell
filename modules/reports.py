from datetime import datetime
from definitions.constants import Constants

class ReportManager:

    def __init__(self, config):
        self.config = config

        self.log_report = []
        self.conf_report = []
        self.binary_report = []
        self.service_report = []
        self.local_report = []
        self.remote_report = []

    def save_report(self, scope):
        filename = self.config.reports_path
        filename +=  f'/Systell_{Constants.SCOPE.get_scope_name(scope)}_Report_' + str(datetime.now())

        if scope == Constants.SCOPE.LOG:  
            report = self.log_report
 
        elif scope == Constants.SCOPE.CONF:  
            report = self.conf_report

        elif scope == Constants.SCOPE.PACKAGE:  
            report = self.binary_report

        elif scope == Constants.SCOPE.SERVICE:  
            report = self.service_report

        elif scope == Constants.SCOPE.LOCAL:  
            report = self.local_report

        elif scope == Constants.SCOPE.REMOTE:
            report = self.remote_report
        
        if report and len(report) > 0:
            with open(filename, 'w') as report_file:
                for item in report:
                    if item.startswith('\n'):
                        report_file.write(item)
                    else:
                        report_file.write(item + "\n")

    def generate_report(self, input, scope):
        if scope == Constants.SCOPE.LOG:
            if input:
                box_char = '-'
                first_line_len = len(input[0])
                delimiter_line = box_char * (first_line_len + 2)
                input.insert(1, delimiter_line)
                input.insert(0, delimiter_line)
                input[1] = '|' + input[1] + '|'

                for item in input:
                    self.log_report.append(item)
                self.log_report.append('\n')

        elif scope == Constants.SCOPE.CONF:
            if input:
                box_char = '-'
                first_line_len = len(input[0])
                delimiter_line = box_char * (first_line_len + 2)
                input.insert(1, delimiter_line)
                input.insert(0, delimiter_line)
                input[1] = '|' + input[1] + '|'

                for item in input:
                    self.conf_report.append(item)
                self.conf_report.append('\n')

        elif scope == Constants.SCOPE.PACKAGE:
            if input:
                box_char = '-'
                first_line_len = len(input[0])
                delimiter_line = box_char * (first_line_len + 2)
                input.insert(1, delimiter_line)
                input.insert(0, delimiter_line)
                input[1] = '|' + input[1] + '|'

                for item in input:
                    self.binary_report.append(item)
                self.binary_report.append('\n')

        elif scope == Constants.SCOPE.SERVICE:
            if input:
                failed_services = 0
                risky_services = 0
                preset_divergence = 0
                service_count = 0

                for item in input:
                    keys = tuple(item.keys())

                    if keys[0] == 'Failed service':
                        failed_services += 1
                    else:
                        service_count += 1
                        if 'Exposure' in item and float(item['Exposure']) >= 6.0:
                            risky_services += 1
                        if len(item) > 4:
                            preset_divergence += 1

                    self.service_report.append(str(item))

                header = []

                header_data = f'#Report: Service report #Total services: {service_count} #Failed services: {failed_services} #With high exposure: {risky_services} #With preset divergence: {preset_divergence}'

                box_char = '-'
                first_line_len = len(header_data)
                delimiter_line = box_char * (first_line_len + 2)
                header.append(delimiter_line)
                header.append('|' + header_data + '|')
                header.append(delimiter_line)

                self.service_report.append('\n')
                self.service_report = header + self.service_report

        elif scope == Constants.SCOPE.LOCAL:
            box_char = '-'
            first_line_len = len(input[0])
            delimiter_line = box_char * (first_line_len + 2)
            input.insert(1, delimiter_line)
            input.insert(0, delimiter_line)
            input[1] = '|' + input[1] + '|'
            
            for item in input:
                self.local_report.append(str(item))
            self.local_report.append('\n')

        elif scope == Constants.SCOPE.REMOTE:
            if input:
                for item in input:
                    self.remote_report.append(item)

                    if item.startswith('Remote: '):
                        width = len(item)
                        separator = '-' * width
                        self.remote_report.append(separator)
                self.remote_report.append('\n')

    def summary(self):
        pass