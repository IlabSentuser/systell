import sys
from modules.controller import Controller
from utils import fprint as fprint
from config import Config
import configparser
try:
    import distro
except ImportError:
    print('distro module not available, please make sure to install it.')
from definitions.constants import Constants
import importlib.util

#Defaults section
CONFIG_FILE = None

if __name__ == "__main__":

    # Check dependencies
    required_dependencies = ['nmap', 'distro', 'psutil', 'systemd']
    not_found_dependencies = []
    for dependency in required_dependencies:
        module = importlib.util.find_spec(dependency)
        if module is None:
            not_found_dependencies.append(dependency)
    if len(not_found_dependencies) > 0:
        print('There are unsatisfied dependencies, please make sure to install them first.')
        sys.exit(1)

    distro = distro.name()
    scope = None
    unattended = False
    reports_path = None
    use_journal = False

    if distro == 'Ubuntu':
        locations_file = Constants.PATH.UBUNTU_LOCATIONS_PATH
    elif distro == 'Arch Linux':
        locations_file = Constants.PATH.ARCHLINUX_LOCATIONS_PATH
    else:
        fprint('The current distribution is not supported. Exitting.')
        exit()

    for index, arg in enumerate(sys.argv):
        if arg == '-h' or arg == '--help':
            print('Usage: flag1 <parameter1> [flagX <parameterX]')
            print(' Flags:')
            print('  -s: defines the scope of the analysis, requires an string separated by comas of the scopes to execute, each scope being a number, for example -s 1,3,5')
            print('  -j: indicates that the journal should be analyzed, it only makes sense if the LOG scope is used and is ignored otherwise')
            print('  -r: defines the path to where the reports will be saved, the path must be a directory and exist, for example -r /home/user/reports/')
            print('  -h or --help: print this message')
            print('Note: in unattended mode the reports path is not mandatory as by default /tmp will be used, however the scope is.')
            unattended = True
            break
        if arg == '-s':
            if index + 1 < len(sys.argv):
                scope = sys.argv[index + 1]
                scope = scope.replace(',', ' ')
            else:
                print("-s flag requires a scope argument, i.e: 1,3,5")
            unattended = True
        
        if arg == '-j':
            use_journal = True

        if arg == '-r':
            if index + 1 < len(sys.argv):
                reports_path = sys.argv[index + 1]
            else:
                print("-r flag requires a path, i.e: /home/user/reports/")
            unattended = True

    if unattended == False:
        print('Define the scope of the analysis by typing the numbers of the desired modules separating them by a space or leave empty for defaults. For example: 1 3 4')
        print('Available scopes: ' + Constants.SCOPE.get_scopes())
        scope = input('Scope: ')

        if str(Constants.SCOPE.LOG) in scope:
            print("Should the journal be analyzed too? Introduce [y] for yes, any other value for no")
            journal_choice = input('Include journal: ')
            if journal_choice is not None and journal_choice == 'y':
                use_journal = True
            else:
                use_journal = False

        print('Introduce the path where reports will be saved or leave blank for defaults (/tmp/). For example: /home/user/reports/')
        reports_path = input('Reports path: ')

    if scope is not None:
        if reports_path is None or reports_path == '':
            reports_path = Constants.PATH.DEFAULT_REPORTS_PATH

        # Use journal flag to false for debugging purposes
        config = Config(distro, locations_file, rules_directory = Constants.PATH.RULES_PATH, scope=scope, reports_path=reports_path, use_journal=use_journal)

        controller = Controller(config)
        controller.execute_scope()
        controller.save_reports()

    