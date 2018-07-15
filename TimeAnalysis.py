#!/usr/local/bin/python3
import argparse
import re


class TimeAnalysis:
    """Check a specified log for a particular timestamp and return snippets of parsed data"""
    def __init__(self, time, install, service, extension, requested_sections):

        self.time = time
        # temp directory in use for test
        self.log_to_parse = '/Users/branden.miars/var/log/{}/{}.{}.log'.format(service, install, extension)
        self.requested_sections = requested_sections
        self.log_map = {'ip': 0, 'domain': 1, '-': 2, 'timestamp': 3, 'holder': 4, 'method': 5,
                        'path': 6, 'protocol': 7, 'code': 8, 'hodler2': 9, 'referrer': 10,
                        'ua': 11}

    def log_parser(self):

        print('Checking {} for the {} timestamp'.format(self.log_to_parse, self.time))
        for section in self.requested_sections:
            new_dict = {}
            tmp = []
            section_to_check = self.log_map.get(section)

            with open(self.log_to_parse, "r") as in_file:
                # Loop over each log line
                for line in in_file:
                    split_line = line.split()
                    split_line = split_line[:11]+[' '.join(split_line[11:])]
                    if self.time in split_line[3]:
                        if split_line[section_to_check] in new_dict:
                            new_dict[split_line[section_to_check]] +=1
                        else:
                            new_dict[split_line[section_to_check]] = 1

            for key, value in new_dict.items():
                tmp_tuple = (value, key)
                tmp.append(tmp_tuple)

            tmp = sorted(tmp, reverse=True)

            print('Top {}:'.format(section))
            
            for count, item in enumerate(tmp):
                temp_item = str(item).replace(',', ' -')
                print(re.sub('[()]', '', temp_item))
                if count == 9:
                    break
            print('-------------------------')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Parse apache or nginx logs for a specific timestamp')
    apache_or_nginx = parser.add_mutually_exclusive_group(required=True)
    information_to_include = parser.add_argument_group('Optional flags', 'Optional information to include in the parse')
    apache_or_nginx.add_argument('--nginx', '-n',
                       action='store_true',
                       help='parse nginx log' )
    apache_or_nginx.add_argument('--apache', '-a',
                       action='store_true',
                       help='parse apache log')

    parser.add_argument("install", type=str, help="install to check")
    parser.add_argument("timestamp", type=str, help="timestemp to check")

    information_to_include.add_argument('--ip', '-i',
                                        action='store_true',
                                        help='include top IP addresses')
    information_to_include.add_argument('--path', '-p',
                                        action='store_true',
                                        help='include top paths requests')
    information_to_include.add_argument('--ua', '-u',
                                        action='store_true',
                                        help='include top User Agents')
    information_to_include.add_argument('--code', '-c',
                                        action='store_true',
                                        help='include top response codes')
    information_to_include.add_argument('--referrer', '-r',
                                        action='store_true',
                                        help='include top referrers')

    section_options = ['path', 'ip', 'ua', 'code', 'referrer']
    requested_sections = []
    args = parser.parse_args()
    for item in section_options:
        if args.__dict__.get(item):
            requested_sections.append(item)
    if not requested_sections:
        requested_sections = ['path', 'ip', 'ua']

    if args.nginx:
        service = 'nginx'
        extension = 'apachestyle'
    else:
        service = 'apache2'
        extension = 'access'

    parse_the_log = TimeAnalysis(args.timestamp, args.install, service, extension, requested_sections)
    parse_the_log.log_parser()

