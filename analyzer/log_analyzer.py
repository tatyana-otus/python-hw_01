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
import traceback
import logging
import configparser
import argparse
from collections import namedtuple

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": ".",
    "LOG_DIR": ".",
    "LOG_FILE": None,
    "LOG_LEVEL": "ERROR",
    "ERROR_LIMIT": 1
}

DEFAULT_CFG_PATH = "./analyzer.cfg"

LogFile = namedtuple('LogFile', 'name date')
ReportStat = namedtuple('ReportStat', 'urls times errors report')
UrlRawStat = namedtuple('UrlRawStat', 'url time error')

log_name_pattern = re.compile(r"nginx-access-ui\.log-(\d{8})\.(log|gz)$")
log_rec_pattern = re.compile(r"\S+\s+"        # $remote_addr
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
                             r"([\d\.]+)$")   # $request_time)


def get_last_log(log_dir):
    """
    Returns the last file name compared by date
    from 'log_dir' directory and matched date
    """

    logging.info("Geting last log file from: {}".format(log_dir))

    file_name = ""
    date = 0
    date_str = ""

    for file in os.listdir(log_dir):
        result = log_name_pattern.match(file)
        if result:
            if date < int(result.group(1)):
                file_name = file
                date_str = result.group(1)
                date = int(result.group(1))

    return LogFile(file_name, date_str)


def gen_record(path):
    """
    Generates valid URL and request_time from 'path'
    if 'error'== True
    """

    log_open = gzip.open if path.endswith('.gz') else open

    with log_open(path, 'rt', encoding='utf-8') as log:
        for line in log:
            yield process_record(line.strip())


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
    for url_raw_stat in gen_record(file_path):
        if url_raw_stat.error:
            error_count += 1
            continue
        if url_raw_stat.url:
            f_time = float(url_raw_stat.time)
            urls_count += 1
            times_count += f_time
            if url_raw_stat.url in report:
                report[url_raw_stat.url].append(f_time)
            else:
                report[url_raw_stat.url] = [f_time]

    return ReportStat(urls_count, times_count, error_count, report)


def calculate_stat(report_stat, report_size):
    """
    Calculating statistics:
    time_sum
    count
    time_max
    time_med for each url in 'raw_report'
    """

    UrlStat = namedtuple('UrlStat', 'time_sum time_med time_max count url')

    logging.info("Calculating statistics ...")

    precision = 3
    full_report = []
    for url, times in report_stat.report.items():
        full_report.append(UrlStat(sum(times),
                           statistics.median(times),
                           max(times),
                           len(times),
                           url
                           ))

    full_report = sorted(full_report, key=lambda kv: kv[0], reverse=True)

    report_for_save = []
    for line in itertools.islice(full_report, 0, report_size):
        time_avg = line.time_sum/line.count
        time_perc = line.time_sum/report_stat.times * 100.0
        count_perc = line.count/report_stat.urls * 100.0

        report_for_save.append({"url": line.url,
                                "count": round(line.count, precision),
                                "time_sum": round(line.time_sum, precision),
                                "time_avg": round(time_avg,  precision),
                                "time_med": round(line.time_med, precision),
                                "time_max": round(line.time_max, precision),
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
            with open(file_path, 'wt', encoding='utf-8') as f_report:
                f_report.write(s.safe_substitute(table_json=json.dumps(report,
                               sort_keys=True)))
    except Exception as e:
        logging.error('Saving report Error')
        raise e

    logging.info("Report {} saved.".format(file_path))


def process_record(rec):
        """
        Parses single string record from log-file,
        returns URL, request_time and error:
        False - if parsing OK
        True - if parsing ERROR
        """

        result = log_rec_pattern.match(rec)
        url = ""
        if result:
            request = re.match(r"\"\S+\s+(.*)\s+\S+\"", result.group(1))
            if request:
                url = request.group(1)
            return UrlRawStat(url, result.group(2), False)
        else:
            logging.debug("Fail: {}".format(rec))
            return UrlRawStat(url, 0, True)


def parse_cfg_opt():
    """
    Getting the config file path
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=DEFAULT_CFG_PATH,
                        nargs='?', dest="cfg_file",
                        help="Path to configuration file")

    args = parser.parse_args()
    return args.cfg_file


def get_cfg(file_path):
    """
    Config options setup
    """
    cfg = config.copy()

    if not os.path.isfile(file_path):
        logging.error('Wrong file or file path: {}'.format(file_path))
        raise FileNotFoundError("Config file not found")

    file_cfg = configparser.ConfigParser()
    file_cfg.read(file_path, encoding='utf-8')
    cfg["LOG_DIR"] = file_cfg.get("Common",
                                  "LOG_DIR",
                                  fallback=cfg["LOG_DIR"])
    cfg["REPORT_DIR"] = file_cfg.get("Common",
                                     "REPORT_DIR",
                                     fallback=cfg["REPORT_DIR"])
    cfg["REPORT_SIZE"] = int(file_cfg.get("Common",
                                          "REPORT_SIZE",
                                          fallback=cfg["REPORT_SIZE"]))
    cfg["LOG_FILE"] = file_cfg.get("Log", "LOG_FILE",
                                   fallback=cfg["LOG_FILE"])
    cfg["LOG_LEVEL"] = file_cfg.get("Log", "LOG_LEVEL",
                                    fallback=cfg["LOG_LEVEL"])
    cfg["ERROR_LIMIT"] = float(file_cfg.get("Common",
                                            "ERROR_LIMIT",
                                            fallback=cfg["ERROR_LIMIT"]))

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
    level = {'INFO': logging.INFO,
             'ERROR': logging.ERROR,
             'DEBUG': logging.DEBUG}
    if log_level not in level:
        raise ValueError('Wrong LOG_LEVEL')

    logging.basicConfig(level=level[log_level],
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        filename=file_path,
                        filemode='w')


def process(log_path, report_size):
    """
    Log-file processing and report generation
    """

    logging.info("Process: {}".format(log_path))
    report_stat = get_raw_stat(log_path)

    logging.info("urls = {} errors = {}".format(report_stat.urls,
                                                report_stat.errors))

    error_limit = 0
    if report_stat.urls:
        error_limit = report_stat.errors/report_stat.urls
    else:
        error_limit = report_stat.errors

    report = []
    if report_stat.report:
        report = calculate_stat(report_stat,
                                report_size)

    return report, error_limit


def main():

    try:
        cfg_path = parse_cfg_opt()

        cfg = get_cfg(cfg_path)
        setup_logging(cfg["LOG_FILE"], cfg["LOG_LEVEL"])

    except (FileNotFoundError, configparser.ParsingError, ValueError) as e:
        logging.error("Config error")
        raise e

    if not is_valid_cfg_options(cfg):
        logging.error("Invalid config: {}".format(cfg))
        return
    log_des = get_last_log(cfg["LOG_DIR"])

    report_path = os.path.join(cfg["REPORT_DIR"],
                               "report-{}.html".format(log_des.date))
    log_path = os.path.join(cfg["LOG_DIR"], log_des.name)

    is_need_process = (os.path.isfile(log_path) and
                       not os.path.isfile(report_path))
    if not is_need_process:
        logging.info("No log-files to process")
        return
    report, error_limit = process(log_path, cfg["REPORT_SIZE"])
    if error_limit > cfg["ERROR_LIMIT"]:
        logging.error("Errors: {}%".format(error_limit))
        return
    else:
        save_as_json(report_path, report)


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        logging.exception(traceback.format_exc())
        logging.error("Exit with KeyboardInterrupt")

    except Exception as e:
        logging.exception(traceback.format_exc())
        logging.error("Exit with error: {}".format(e))
