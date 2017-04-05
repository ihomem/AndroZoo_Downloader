import logging
import json
import os
import requests
from tqdm import tqdm
import hashlib
from contextlib import closing

import csv
import codecs
from itertools import islice


class ApkDownloader(object):

    def __init__(self):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        self.config_file_path = os.path.join('config', 'APK_PATH.json')
        self.config_file = self.read_config_file(self.config_file_path)

        self.apk_list_path = self.config_file['config']['apk_dataset']['apk_url']
        self.apk_store_path = self.config_file['config']['remote']['apk_path']
        self.API_key =  self.config_file['config']['remote']['api_key']

        self.APK_filename_list = self.get_all_apk_filenames_from_source('None')

    def read_config_file(self, configPath):
        self.logger.debug("Config Path: %s" % str(configPath))
        with open(configPath) as data_file:
            data = json.load(data_file)
            # self.logger.debug("APK Config Path (in func): %s" % str(data['config'][apk_path_type]['apk_path']))

            # return str(data['config'][apk_path_type]['apk_path'])
            return data

    def download_apk(self, file_name):
        success = False
        #self.logger.debug('Getting APK from REMOTE path: {}'.format(self.apk_store_path_type))
        self.logger.debug('Getting APK from REMOTE path: {}'.format(self.apk_store_path))
        # https://androzoo.uni.lu/api/download?apikey=${APIKEY}&sha256=${SHA256}
        params = {'apikey': self.API_key, 'sha256': file_name}
        # resp = requests.post(self.apk_files_path, data=params)
        resp = requests.get(self.apk_store_path, data=params, stream=True)
        self.logger.debug('Response Code: \n {}:{}'.format(resp.status_code, resp.reason))
        # self.logger.debug('Response: \n {}'.format(resp.text))
        extension = '.apk'
        downloads_filepath = os.path.join('downloads', file_name + extension)
        if resp.ok:
            total_size = int(resp.headers.get('content-length'))
            self.logger.info('File Length: {}'.format(total_size))
            with open(downloads_filepath, 'wb') as file_handle:
                # if the file is large we do the writing in chunks
                # tqdm is a library for a portable progressbar (Default unit is "it" --> number of iterations)
                for block in tqdm(resp.iter_content(1024), unit='B', total=total_size / 1024, unit_scale=True):
                    file_handle.write(block)
                    # currsize = (file_handle/1000000)
                    # apk_file = file_handle
                    # apk_file_path = temp_filepath

            # Check the hash if the transfer has completed successfully
            #apk = apk_file.ApkFile(temp_filepath)
            self.logger.debug('Local SHA 256: {}'.format(self.get_sha256_hash(downloads_filepath)))
            success = True
        else:
            success = False
            self.logger.error(
                "Something went wrong with the file download: {} - {}".format(resp.status_code, resp.reason))

            # return apk_file
            # return apk_file_path

        #return apk
            return success

    def get_all_apk_filenames_from_source(self, mal_state='None'):
        url = self.apk_list_path
        self.logger.debug("Current APK Source: {}".format(url))
        apk_filenames = []
        with closing(requests.get(url, stream=True)) as r:
            reader = csv.reader(codecs.iterdecode(r.iter_lines(), 'utf-8'))
            # Picking all the filenames from the data source
            # for row in reader:
            #     apk_filenames.append(row[0])
            #     self.logger.debug('APK SHA256 (name): {}'.format(row[0]))

            # ***************************************
            # Picking only the first 10 file names
            # ***************************************
            self.row_zero_header = next(reader)
            self.logger.debug("Header Row: {}".format(self.row_zero_header))
            vt_detection_idx = self.row_zero_header.index('vt_detection')
            self.logger.debug("vt_detection INDEX: {}".format(vt_detection_idx))
            for idx, row in enumerate(islice(reader, 10)):
                if mal_state == 'malicious':
                    if int(row[vt_detection_idx]) > 0:
                        apk_filenames.append(row[0])
                        self.logger.debug('APK SHA256 (name): {}'.format(row[0]))
                        # print("SHA256: {}".format(row[0]))
                        # print(row)
                elif mal_state == 'benign':
                    if int(row[vt_detection_idx]) == 0:
                        apk_filenames.append(row[0])
                        self.logger.debug('APK SHA256 (name): {}'.format(row[0]))
                        # print("SHA256: {}".format(row[0]))
                        # print(row)
                elif mal_state == 'None':
                    apk_filenames.append(row[0])
                    self.logger.debug('APK SHA256 [{}] (name): {}'.format(len(apk_filenames),row[0]))

        return  apk_filenames

    def get_sha256_hash(self, filepath, block_size=65536):
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
        return str(sha256.hexdigest()).upper()

    def do_download(self):
        for apk_file_name in self.APK_filename_list:
            self.download_apk(apk_file_name)

def main():
    apk_downloader = ApkDownloader()
    apk_downloader.do_download()


if __name__ == "__main__":
    main()