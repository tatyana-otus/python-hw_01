#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import os
import re
import statistics
import json
from string import Template
import itertools
import gzip
import sys
import getopt
import traceback
import logging
import configparser

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": ".",
    "LOG_DIR": ".",
    "LOG_FILE": None
}

LOG_LEVEL = logging.INFO
DEFAULT_CFG_PATH = "./analyzer.cfg"

LOG_FILE_NAME_PATTERN = r"nginx-access-ui\.log-(\d{8})\.(log|gz)$"


def get_last_log(log_dir):
    """
    Returns the last file name compared by date
    from 'log_dir' directory and matched date
    """

    logging.info("Geting last log file from: {}".format(log_dir))

    file_name = ""
    date = 0
    date_str = ""
    for cur_dir, subdirs, files in os.walk(log_dir):
        for file in files:
            result = re.match(LOG_FILE_NAME_PATTERN, file)
            if result:
                if date < int(result.group(1)):
                    file_name = file
                    date_str = result.group(1)
                    date = int(result.group(1))

    return file_name, date_str


def gen_record(path):
    """
    Generates valid URL and request_time if 'error'== 0
    from 'path'
    """
    assert(path.endswith('.gz') or path.endswith('.log'))

    is_gz = path.endswith('.gz')

    with gzip.open(path, 'rt', encoding='ascii') if is_gz else open(path, 'rt', encoding='ascii') as log:
        for line in log:
            url, time, error = process_record(line.strip())
            yield url, time, error


def get_raw_stat(file_path):
    """
    Generates 'report' - all request_times for each URL
    total number of urls - 'urls_count'
    total time - 'times_count'
    total number of errors - 'error_count'
    """

    report = {}
    urls_count = 0
    times_count = 0
    error_count = 0
    for url, time, error in gen_record(file_path):
        error_count += error
        if url:
            urls_count += 1
            error_count += error
            times_count += float(time)
            if url in report:
                report[url].append(float(time))
            else:
                report[url] = [float(time)]

    return urls_count, times_count, error_count, report


def calculate_stat(raw_report, urls_count, times_count, report_size):
    """
    Calculating statistics:
    time_sum
    count
    time_max
    time_med for each url in 'raw_report'
    """

    logging.info("Calculating statistics ...")

    precision = 3
    full_report = []
    for url, times in raw_report.items():
        full_report.append((sum(times),
                            statistics.median(times),
                            max(times),
                            len(times),
                            url
                            ))

    full_report = sorted(full_report, key=lambda kv: kv[0], reverse=True)

    report_for_save = []
    for line in itertools.islice(full_report, 0, report_size):
        url = line[4]
        count = line[3]
        time_sum = line[0]
        time_avg = line[0]/count
        time_med = line[1]
        time_max = line[2]
        time_perc = line[0]/times_count * 100.0
        count_perc = line[3]/urls_count * 100.0

        report_for_save.append({"url": url,
                                "count": round(count, precision),
                                "time_sum": round(time_sum, precision),
                                "time_avg": round(time_avg,  precision),
                                "time_med": round(time_med, precision),
                                "time_max": round(time_max, precision),
                                "time_perc": round(time_perc, precision),
                                "count_perc": round(count_perc, precision)
                                })

    return report_for_save


def save_as_json(file_path, report, sample_report='report.html'):
    """
    Saves report as json file
    """

    logging.info("Saving report ...")
    try:
        with open(sample_report, 'rt') as html_report:
            s = Template(html_report.read())
            with open(file_path, 'wt', encoding='ascii') as report_file:
                report_file.write(s.safe_substitute(table_json=json.dumps(report, sort_keys=True)))
    except Exception as e:
        raise

    logging.info("Report "+file_path+" saved.")


def process_record(rec):
        """
        Parses single string record from log-file,
        returns URL, request_time and
        0 - if parsing OK
        1 - if parsing ERROR
        """

        result = re.match(r"\S+\s+"        # $remote_addr
                          r"\S+\s+"        # $remote_user
                          r"\S+\s+"        # $http_x_real_ip
                          r"\[.*\]\s+"     # [$time_local]
                          r"(\".*?\")\s+"  # "$request"
                          r"\S+\s+"        # $status
                          r"\S+\s+"        # $body_bytes_sent
                          r"\".*?\"\s+"    # "$http_referer"
                          r"\".*?\"\s+"    # "$http_user_agent"
                          r"\".*?\"\s+"    # "$http_x_forwarded_for"
                          r"\".*?\"\s+"    # "$http_X_REQUEST_ID"
                          r"\".*?\"\s+"    # "$http_X_RB_USER"
                          r"([\d\.]+)$",   # $request_time
                          rec)
        url = ""
        if result:
            request = re.match(r"\"\S+\s+(.*)\s+\S+\"", result.group(1))
            if request:
                url = request.group(1)
            return (url, result.group(2), 0)
        else:
            logging.debug("Fail: {}".format(rec))
            return (url, 0, 1)


def get_cfg(argv):
    """
    Config options setup
    """

    cfg = config.copy()
    file_path = DEFAULT_CFG_PATH
    try:
        opts, args = getopt.getopt(argv, "", ["config="])
    except getopt.GetoptError:
        pass
    for opt, arg in opts:
        if opt == '--config':
            file_path = arg

    with open(file_path, 'rt') as f:
        pass

    file_cfg = configparser.ConfigParser()
    file_cfg.read(file_path, encoding='ascii')
    cfg["LOG_DIR"] = file_cfg.get("Common",
                                  "LOG_DIR",
                                  fallback=cfg["LOG_DIR"])
    cfg["REPORT_DIR"] = file_cfg.get("Common",
                                     "REPORT_DIR",
                                     fallback=cfg["REPORT_DIR"])
    cfg["REPORT_SIZE"] = int(file_cfg.get("Common",
                                          "REPORT_SIZE",
                                          fallback=cfg["REPORT_SIZE"]))
    cfg["LOG_FILE"] = file_cfg.get("Log", "LOG_FILE", fallback=None)

    return cfg


def is_valid_cfg_options(cfg):
    """
    Validates config options
    """

    return (os.path.isdir(cfg["LOG_DIR"]) and
            os.path.isdir(cfg["REPORT_DIR"]) and
            cfg["REPORT_SIZE"] > 0)


def setup_logging(file_path, log_level):
    """
    Logging configuration setup
    """

    logging.basicConfig(level=log_level,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        filename=file_path,
                        filemode='w')


def process(log_path, report_size):
    """
    Log-file processing and report generation
    """

    logging.info("Process: {}".format(log_path))
    urls_count, times_count, error_count, raw_report = get_raw_stat(log_path)

    logging.info("urls = {} errors = {}".format(urls_count, error_count))

    error_perc = 1
    if urls_count:
        error_perc = error_count/urls_count

    report = []
    if raw_report:
        report = calculate_stat(raw_report, urls_count, times_count, report_size)

    return report, error_perc


def main(argv=sys.argv):

    try:
        cfg = get_cfg(argv[1:])
        setup_logging(cfg["LOG_FILE"], LOG_LEVEL)

    except (FileNotFoundError, configparser.ParsingError, ValueError) as e:
        print("Exit with error: {}".format(e))
        sys.exit(2)

    try:
        if is_valid_cfg_options(cfg):
            log_file, date = get_last_log(cfg["LOG_DIR"])

            report_path = cfg["REPORT_DIR"]+'/'+"report-"+date+".html"
            log_path = cfg["LOG_DIR"]+'/'+log_file

            is_need_process = (os.path.isfile(log_path) and
                               not os.path.isfile(report_path))

            if is_need_process:
                report, error_perc = process(log_path, cfg["REPORT_SIZE"])
                if error_perc > 1:
                    logging.error("Errors: {}%".format(error_perc))
                    return
                else:
                    save_as_json(report_path, report)
            else:
                logging.info("No log-files to process")
                return

        else:
            logging.error('Invalid config: '+str(cfg))

    except KeyboardInterrupt:
        logging.error(traceback.format_exc())
        logging.error("Exit with KeyboardInterrupt")
        sys.exit(2)

    except Exception as e:
        logging.exception(traceback.format_exc())
        logging.error("Exit with error: {}".format(e))
        sys.exit(2)


if __name__ == "__main__":

    main()
