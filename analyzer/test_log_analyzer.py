import unittest
import log_analyzer as la
import os
import configparser
import shutil
import sys
import filecmp
import logging


class ConfigFileTest(unittest.TestCase):

    good_config_2 = "[Common]\n"\
                    "REPORT_SIZE: 50\n"\
                    "LOG_DIR: ./test/log\n"\
                    "REPORT_DIR: ./test/report\n"\
                    "ERROR_LIMIT: 0.5\n\n"\
                    "[Log]\n"\
                    "LOG_FILE:log_analyzer.log\n"\
                    "LOG_LEVEL:DEBUG"

    good_config_1 = "[Common]\n"\
                    "REPORT_SIZE: 987654321"

    bad_config_1 = "[Common]\n"\
                   "REPORT_SIZE: 50XXX\n"\
                   "LOG_DIR: .\n"\
                   "REPORT_DIR: .\n\n"\
                   "[Log]\n"\
                   "LOG_FILE:log_analyzer.log"

    bad_config_2 = "[Common]\n"\
                   "REPORT_SIZE: 50\n"\
                   "LOG_DIR: .\n"\
                   "hkhh\n"\
                   "REPORT_DIR: .\n\n"\
                   "[Log]\n"\
                   "LOG_FILE:log_analyzer.log"

    def test_no_config_file(self):
        with self.assertRaises(FileNotFoundError):
            la.get_cfg('nonexistent_file.cfg')

    def test_good_config_files(self):
        def_cfg = la.config.copy()
        with open('good_cfg_file.cfg', 'wt') as f:
            f.write(self.good_config_1)
        new_config = la.get_cfg('good_cfg_file.cfg')
        self.assertEqual(new_config, {"REPORT_SIZE": 987654321,
                                      "REPORT_DIR": def_cfg["REPORT_DIR"],
                                      "LOG_DIR": def_cfg["LOG_DIR"],
                                      "LOG_FILE": def_cfg["LOG_FILE"],
                                      "LOG_LEVEL": def_cfg["LOG_LEVEL"],
                                      "ERROR_LIMIT": def_cfg["ERROR_LIMIT"]
                                      })
        os.remove("good_cfg_file.cfg")

        with open('good_cfg_file.cfg', 'wt') as f:
            f.write(self.good_config_2)
        new_config = la.get_cfg('good_cfg_file.cfg')
        self.assertEqual(new_config, {"REPORT_SIZE": 50,
                                      "REPORT_DIR": "./test/report",
                                      "LOG_DIR": "./test/log",
                                      "LOG_FILE": "log_analyzer.log",
                                      "LOG_LEVEL": 'DEBUG',
                                      "ERROR_LIMIT": 0.5
                                      })
        os.remove("good_cfg_file.cfg")

    def test_bad_config_files(self):
        with open('bad_config_file.cfg', 'wt') as f:
            f.write(self.bad_config_1)
        with self.assertRaises(ValueError):
            la.get_cfg('bad_config_file.cfg')
        os.remove("bad_config_file.cfg")

        with open('bad_config_file.cfg', 'wt') as f:
            f.write(self.bad_config_2)
        with self.assertRaises(configparser.ParsingError):
            la.get_cfg('bad_config_file.cfg')
        os.remove("bad_config_file.cfg")


class GetLastFileTest(unittest.TestCase):

    def test_log_files(self):
        shutil.rmtree("test_log", ignore_errors=True, onerror=None)
        os.mkdir("test_log")

        os.mknod('test_log/nginx-access-ui.log-20181201.log')
        os.mknod('test_log/nginx-access-ui.log-20191212.gzip')
        os.mknod('test_log/nginx-access-ui.log-20181001.log')

        log_file, date = la.get_last_log('test_log')
        self.assertEqual(log_file, "nginx-access-ui.log-20181201.log")

        shutil.rmtree("test_log", ignore_errors=True, onerror=None)

    def test_gz_files(self):
        shutil.rmtree("test_log", ignore_errors=True, onerror=None)
        os.mkdir("test_log")

        os.mknod('test_log/nginx-access-ui.log-20181201.log')
        os.mknod('test_log/nginx-access-ui.log-20191201.gz')
        os.mknod('test_log/nginx-access-ui.log-20161224.gz')
        os.mknod('test_log/nginx-access-ui.log-20191212.gzip')

        log_file, date = la.get_last_log('test_log')
        self.assertEqual(log_file, "nginx-access-ui.log-20191201.gz")

        shutil.rmtree("test_log", ignore_errors=True, onerror=None)


class ReportGenerationTest(unittest.TestCase):

    result_report = [{'url': '/api/v2/banner/3', 'count': 3,
                      'time_perc': 53.333,
                      'time_sum': 0.8,
                      'time_max': 0.4,
                      'count_perc': 50.0,
                      'time_med': 0.3,
                      'time_avg': 0.267
                      },

                     {'url': '/api/v2/banner/2', 'count': 2,
                      'time_perc': 40.0,
                      'time_sum': 0.6,
                      'time_max': 0.4,
                      'count_perc': 33.333,
                      'time_med': 0.3,
                      'time_avg': 0.3
                      },

                     {'url': '/api/v2/banner/1', 'count': 1,
                      'time_perc': 6.667, 'time_sum': 0.1,
                      'time_max': 0.1,
                      'count_perc': 16.667,
                      'time_med': 0.1,
                      'time_avg': 0.1
                      }]

    def test_good_log(self):
        report, error_limit = la.log_anal_proc("./test_data/good_sample.log",
                                               10)
        self.assertEqual(error_limit, 0)
        self.assertEqual(report, self.result_report)

        report, error_limit = la.log_anal_proc("./test_data/good_sample.log",
                                               2)
        self.assertEqual(error_limit, 0)
        self.assertEqual(report, self.result_report[:2])

        report, error_limit = la.log_anal_proc("./test_data/good_sample.log",
                                               1)
        self.assertEqual(error_limit, 0)
        self.assertEqual(report, self.result_report[:1])

    def test_bad_log(self):
        report, error_limit = la.log_anal_proc("./test_data/bad_sample.log",
                                               10)
        self.assertEqual(error_limit, 2.0)


class LogAnalizerMainTest(unittest.TestCase):

    def test_plain_log(self):
        shutil.rmtree("./test_data/test_reports",
                      ignore_errors=True, onerror=None)
        os.mkdir("./test_data/test_reports")

        os.system("python3 ./log_analyzer.py --config ./test_data/test.cfg")

        self.assertTrue(filecmp.cmp(
                        './test_data/test_reports/report-20181024.html',
                        './test_data/report-20181024.html')
                        )

        shutil.rmtree("./test_data/test_reports",
                      ignore_errors=True, onerror=None)

    def test_gz_log(self):
        shutil.rmtree("./test_data/test_reports",
                      ignore_errors=True, onerror=None)
        os.mkdir("./test_data/test_reports")

        os.system("python3 ./log_analyzer.py --config ./test_data/test_gz.cfg")

        self.assertTrue(filecmp.cmp(
                       './test_data/test_reports/report-20181024.html',
                       './test_data/report-20181024.html')
                        )

        shutil.rmtree("./test_data/test_reports",
                      ignore_errors=True, onerror=None)


if __name__ == '__main__':

    unittest.main()
