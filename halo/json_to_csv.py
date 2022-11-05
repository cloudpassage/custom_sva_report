import csv
from datetime import datetime
from halo.utility import Utility


class JSONToCSV(object):

    def prepare_csv_file(self, output_directory):
        # Preparing CSV file for writing
        current_time = Utility.date_to_iso8601(datetime.now())
        file_name = 'custom_sva_scan_report_' + current_time + '.csv'
        file_name = file_name.replace(':', '-')
        if output_directory == "":
            absolute_path = file_name
        else:
            absolute_path = output_directory + "/" + file_name
        return absolute_path, file_name, current_time