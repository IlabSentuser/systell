import configparser
from definitions.constants import Constants
import os

class Config:
    
    def __init__(self, distro, locations_file, rules_directory, scope='', reports_path = Constants.PATH.DEFAULT_REPORTS_PATH):
        self.distro = distro
        self.locations_file = locations_file
        self._load_locations()
        self.custom_definitions = None

        self.get_custom_definitions()

        if scope == '':
            # By default the smart scope is not considered for privacy reasons, others scopes are not considered either either for performance or network security reasons. These must be explicitly specified.
            self.scope = [1,2,3,4,5]
        else:
            self.scope = []
            for item in scope.split(' '):
                self.scope.append(int(item))
        self.reports_path = reports_path
    
    def _load_locations(self):
        self.locations_config = configparser.ConfigParser()
        self.locations_config.read(self.locations_file)

    def get_value(self, section, key):
        return self.locations_config.get(section, key)
    
    def get_custom_definitions(self):
        if self.custom_definitions is None:
            if os.path.exists(Constants.PATH.CUSTOM_DEFINITIONS_PATH):
                custom_definitions = configparser.ConfigParser()
                custom_definitions.read(Constants.PATH.CUSTOM_DEFINITIONS_PATH)

                self.custom_definitions = custom_definitions
                return self.custom_definitions
            else:
                return None
        else:
            return self.custom_definitions