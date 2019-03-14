import logging
import subprocess
import zipfile
import os
import sys
import argparse
import json
import requests
import time
from io import StringIO
import urllib3
import email
from email import encoders
import smtplib
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.message import EmailMessage
from email.utils import make_msgid
import mimetypes

import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import numpy as np
import shutil
from PIL import Image

from resizeimage import resizeimage

class Blackhub():
    project_ids= {"UFM":"1234566", "UFMAPL":"1234567", "NEO":"ab654d5e-021a-4099-b561-724f224050cc", "MFT":"123455",'HPCX':'12345'}

    def __init__(self,username,password,recepient_list ,release, project_name,project_file_path):
        self.URL = 'https://blackduck-hub.mellanox.com/'
        self.username = username
        self.password = password
        self.recepint_list = str(recepient_list).split(',')
        self.aSeesion = requests.session()
        self.csrf = None
        self.release = release
        self.project_name = project_name
        self.project_file_path = project_file_path
        self.splited_files_dir = None
        self.verison_id = None
        self.report_id = None
        self.project_id = None
        self.blackduck_files_path= None
        self.zip_file_location = os.getcwd() +os.sep + 'scan.cli-4.6.1.zip'
        self.zip_folder_destination = os.sep + 'tmp' + os.sep + 'scan.cli-4.6.1'+ os.sep
        self.zip_script_path = self.zip_folder_destination + 'scan.cli-4.6.1' + os.sep +'bin' + os.sep + 'scan.cli.sh'
        self.plots_path = os.getcwd() + os.sep + 'graphs'


        self.splitScan()

        #Disable warning from requests libary
        urllib3.disable_warnings()
        self.authenticate(self.username,self.password)
        self.isServerUp()
        self.unzip()
        self.setGlobalPassword()
        self.setProjecId(project_name=self.project_name)
    def isServerUp(self):

        logging.info("check if Blackduck hub server is up....")
        cookies = {
            '_ga': 'GA1.2.670127896.1502020316',
            'optimizelyEndUserId': 'oeu1515931479510r0.043819977420917144',
            '__utma': '194694719.670127896.1502020316.1534161606.1534161606.1',
            '__utmz': '194694719.1534161606.1.1.utmcsr=wikinox.mellanox.com|utmccn=(referral)|utmcmd=referral|utmcct=/display/IT/KVM%20installation%20and%20SRIOV%20cx3',
            'ls': 'gseo',
            'sub': 'true',
            'username': 'Arielwe',
            'TS01e51510': '018428d7a4e2f0813dfd9b9fc47d3a8467d58d92793e485271776b63818dd992fe494549bde69d1cf2a387d03982dfb8e678def8519ceaecdca4b5fb7ba84c768f4ab80e62b0e624c861a97febbca32f29a9ab7283',
        }

        headers = {
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
        }

        response = requests.get('https://blackduck-hub.mellanox.com/', headers=headers, cookies=cookies, verify=False)
        if response.status_code == 200:
            logging.info("Blackduck hub server is Up!")
        else:
            logging.error("Blackduck hub server is down!\n exiting script...")

    def unzip(self):
        path_to_zip_file = self.zip_file_location
        directory_to_extract_to = self.zip_folder_destination
        # check if directory exist...
        if (os.path.isdir(self.zip_folder_destination) == False):
            logging.info("Unzip scan.zip file into \\tmp\\.....") 
            with zipfile.ZipFile(path_to_zip_file, 'r') as zip_ref:
                try:
                    zip_ref.extractall(directory_to_extract_to)
                except Exception as e:
                    logging.error("Exception in Unziping the file...")
                    sys.exit(1)
            logging.info("Unzip finsished successfully...")
            return
        logging.debug("folder exist.. skip unzip")

    def setGlobalPassword(self):
        logging.info("Setting global password before running the script")
        try:
            os.environ['BD_HUB_PASSWORD'] = self.password
        except Exception as e:
            logging.error("Couldn't set global variable")
            sys.exit(1)
     
        logging.debug("setting global password successded")

    def changeFilePermissions(self):
        logging.debug("Changing permission for script to 777")
        try:
            os.chmod(self.zip_script_path, 777)
        except Exception as e:
            logging.error("Exception in changing permission to file")
        logging.info("script file permission were changed to 777 successfully")

    def scan_file(self, file_path):

        val = subprocess.check_call('./' + self.zip_script_path.split('/')[5] + "%s %s %s %s %s %s %s %s" % (
        str(" --host blackduck-hub.mellanox.com"), str("--port 443"), \
        str("--scheme https "), str("--username " + self.username) \
            , str("--insecure"), str("--release " + self.release) \
            , str("--project " + self.project_name), str(file_path)), shell=True)

        return val

    def scan(self):
        '''./scan.cli.sh --host blackduck-hub.mellanox.com --port 443 --scheme https --username arielwe  --insecure
        --release ufm-6.1.0-6.el7.x86_64

        .tgz --project UFM_Test /qa/qa/security/ufm/ufm-6.1.0-6.el7.x86_64.tgz
'''
        logging.info("Start Scanning....\nScan usually takes 1-2 hours...\n")
        logging.info("Make sure the script exist under: " + self.zip_script_path)
        part = 0
        #add surfix of 'Automation' to all projects

        self.project_name = self.project_name + '_Automation'
        #get list of splited file
        file_names = os.listdir(self.splited_files_dir)
        for file_name in file_names:
            file_path = self.splited_files_dir + os.sep + file_name
            if os.path.isfile(self.zip_script_path) == True:
                logging.debug("Script exists under " + self.zip_script_path)
                self.changeFilePermissions()
                tries = 5
                for i in range(tries):
                    try:
                        logging.debug("Trying to scan part " + str(part + 1))
                        dir = '/'.join(self.zip_script_path.split("/")[0:5])
                        os.chdir(dir)
                        val = self.scan_file(file_path= file_path)
                    except KeyError as e:
                        print("Exception in runnong subproceess" + str(e))
                        logging.error("trying " + tries + " attemps more")
                        if i < tries - 1:  # i is zero indexed
                            continue
                        else:
                            raise
                    break
                logging.debug("Scan of part " + str(part +1 ) + "is completed successfully.")
                part+= 1
                time.sleep(15)
            else:
                logging.error("script is not existing under " + self.zip_script_path +"\n" + "Exiting")
                sys.exit(1)
        logging.info("Scanning all files is completed!")

    def setProjecId(self, project_name):

        logging.info("Setting project ID")
        for key, value in Blackhub.project_ids.items():
            if key == project_name:
                logging.debug("project_id is : " + value)
                self.project_id = value
                return
        logging.error("project id wasn't found in project ids hash")

    def setVersionId(self):
        project_id = self.project_id
        url = 'https://blackduck-hub.mellanox.com:443/api/projects/project_id/versions'
        url = url.replace("project_id", project_id)

        cookies = {
            '_ga': 'GA1.2.670127896.1502020316',
            'optimizelyEndUserId': 'oeu1515931479510r0.043819977420917144',
            '__utma': '194694719.670127896.1502020316.1534161606.1534161606.1',
            '__utmz': '194694719.1534161606.1.1.utmcsr=wikinox.mellanox.com|utmccn=(referral)|utmcmd=referral|utmcct=/display/IT/KVM%20installation%20and%20SRIOV%20cx3',
            'ls': 'gseo',
            'sub': 'true',
            'username': 'Arielwe',
            'TS01e51510': '018428d7a4e2f0813dfd9b9fc47d3a8467d58d92793e485271776b63818dd992fe494549bde69d1cf2a387d03982dfb8e678def8519ceaecdca4b5fb7ba84c768f4ab80e62b0e624c861a97febbca32f29a9ab7283',
            'AUTHORIZATION_BEARER': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodWJfaWQiOiI0ZmU4ZWU3OS1jMjEyLTRiODMtOGY0Yi1hZDQ5Yzc2N2QyNjYiLCJ1c2VyX25hbWUiOiJhcmllbHdlIiwic2NvcGUiOlsid3JpdGUiLCJyZWFkIiwiY2xpZW50X21hbmFnZW1lbnQiXSwiY3NyZiI6IjVsVlE3NlR1TENOdGR3cnhYQ1hDNFVvWUIyNEh3SzRDVFk0ZnRGbGJWUUNIOHdFNDdvTW9ONWY1djhyU2FBWTUiLCJleHAiOjE1NDczOTgwNDcsImF1dGhvcml0aWVzIjpbIlBFUk1JU1NJT05fQ0xBSU1fREVMRVRFIiwiUEVSTUlTU0lPTl9DT05GSUdfQ09NTU9OIiwiUEVSTUlTU0lPTl9SRUxFQVNFX0xJU1QiLCJQRVJNSVNTSU9OX0JBREdFX1JFQUQiLCJQRVJNSVNTSU9OX1BST0pFQ1RfUkVBRCIsIlBFUk1JU1NJT05fVVNFUk1HTVRfREVMRVRFIiwiUEVSTUlTU0lPTl9DTEFJTV9SRUFEIiwiUEVSTUlTU0lPTl9UQUdfUkVBRCIsIlBFUk1JU1NJT05fUkVMRUFTRV9DUkVBVEUiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9ERUxFVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfUkVBRCIsIlBFUk1JU1NJT05fQUNUSVZJVFlTVFJFQU1fUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9SRUFEIiwiUEVSTUlTU0lPTl9DTEFJTV9VUERBVEUiLCJQRVJNSVNTSU9OX1VTRVJNR01UX1VQREFURSIsIlBFUk1JU1NJT05fS1VET19SRUFEIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9SRUFEIiwiUEVSTUlTU0lPTl9TQ0FOX0RFTEVURSIsIlBFUk1JU1NJT05fVlVMTkVSQUJJTElUWV9SRUFEIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fQ1JFQVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9DUkVBVEUiLCJQRVJNSVNTSU9OX1BST0pFQ1RfTElTVCIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX1JFQUQiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfREVMRVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9VUERBVEUiLCJQRVJNSVNTSU9OX1NDQU5fQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fUkVBRCIsIlBFUk1JU1NJT05fQVNTRVRfUkVGRVJFTkNFX0RFTEVURSIsIlBFUk1JU1NJT05fUE9MSUNZX1JVTEVfREVMRVRFIiwiUEVSTUlTU0lPTl9MSUNFTlNFX1VQREFURSIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX0NSRUFURSIsIlBFUk1JU1NJT05fS1VET19ERUxFVEUiLCJQRVJNSVNTSU9OX0JPTV9SRUFEIiwiUEVSTUlTU0lPTl9LVURPX0NSRUFURSIsIlBFUk1JU1NJT05fUkVMRUFTRV9SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX0NSRUFURSIsIlBFUk1JU1NJT05fVEVBTU1FTUJFUl9SRUFEIiwiUEVSTUlTU0lPTl9VU0VSTUdNVF9SRUFEIiwiUEVSTUlTU0lPTl9SRVZJRVdfUkVBRCIsIlBFUk1JU1NJT05fVVJMTElOS19SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX1NFQVJDSCJdLCJqdGkiOiI1MDZkMTVmYS00MjkwLTQzNDgtYmFiZS02NmIyNDIwMTRkNjUiLCJjbGllbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtMDAwMC0wMDAwMDAwMDAwMDEifQ.jmIZIDjYBZalpAQE2y1DQ3BfQg0AsIxw60vJIzrVOcU',
        }

        headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': 'https://blackduck-hub.mellanox.com/api/projects/ab654d5e-021a-4099-b561-724f224050cc/versions',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }


        response = self.aSeesion.get(
            url=url,
            headers=headers, cookies=cookies, verify=False)
        if response.status_code == 200:
            logging.debug ("REST API for getting all versions succeeded")
            try:
                logging.debug("Converting response content to json format")
                data = json.loads(response._content)
                self.verison_id = str(list(data['items']).pop()['_meta']['href']).split('/')[7]
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)
            logging.info("version_id is : " + self.verison_id)
        else:
            logging.error("Couldn't retrevied version id\nexiting...")

    def isScanDone(self):
        pass

    def splitScan(self):
        if not (os.path.exists(os.getcwd() + os.sep +'splited_files')):
            os.mkdir('splited_files')
        todir=os.getcwd()+ os.sep + 'splited_files'
        self.splited_files_dir = todir
        fromfile=self.project_file_path

        logging.info("Start to split files into 100MB chucnks into" + todir)
        kilobytes = 1024
        megabytes = kilobytes * 1000
        chunksize = int(100 * megabytes)

        if not os.path.exists(todir):  # caller handles errors
            os.mkdir(todir)  # make dir, read/write parts
        else:
            for fname in os.listdir(todir):  # delete any existing files
                os.remove(os.path.join(todir, fname))
        partnum = 0
        input = open(fromfile, 'rb')  # use binary mode on Windows
        while 1:  # eof=empty string from read
            chunk = input.read(chunksize)  # get next part <= chunksize
            if not chunk: break
            partnum = partnum + 1
            filename = os.path.join(todir, ('part%04d' % partnum))
            fileobj = open(filename, 'wb')
            fileobj.write(chunk)
            fileobj.close()  # or simply open(  ).write(  )
        input.close()
        assert partnum <= 9999  # join sort fails if 5 digits
        logging.debug("splited files function is done, scan file was divided into " + str(partnum) + "parts")
        return partnum

    def downloadCSVReport(self):
        report_id = self.report_id
        url = 'https://blackduck-hub.mellanox.com/api/reports/b9c3a42e-6390-4409-bf80-40fef6d5f2b3'
        url = url.replace("report_id", report_id)

        cookies = {
            '_ga': 'GA1.2.670127896.1502020316',
            'optimizelyEndUserId': 'oeu1515931479510r0.043819977420917144',
            '__utma': '194694719.670127896.1502020316.1534161606.1534161606.1',
            '__utmz': '194694719.1534161606.1.1.utmcsr=wikinox.mellanox.com|utmccn=(referral)|utmcmd=referral|utmcct=/display/IT/KVM%20installation%20and%20SRIOV%20cx3',
            'ls': 'gseo',
            'sub': 'true',
            'username': 'Arielwe',
            'AUTHORIZATION_BEARER': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodWJfaWQiOiI0ZmU4ZWU3OS1jMjEyLTRiODMtOGY0Yi1hZDQ5Yzc2N2QyNjYiLCJ1c2VyX25hbWUiOiJhcmllbHdlIiwic2NvcGUiOlsid3JpdGUiLCJyZWFkIiwiY2xpZW50X21hbmFnZW1lbnQiXSwiY3NyZiI6IjcrZVJldXlacjRpaG9IWEtpQlkxM056Z0RBY0JCZmUyYkNhNExSNTVUUGxvN21MbXlZVzdLY0ZKRFBORWxudVUiLCJleHAiOjE1NDcwNTIwNjUsImF1dGhvcml0aWVzIjpbIlBFUk1JU1NJT05fQ0xBSU1fREVMRVRFIiwiUEVSTUlTU0lPTl9DT05GSUdfQ09NTU9OIiwiUEVSTUlTU0lPTl9SRUxFQVNFX0xJU1QiLCJQRVJNSVNTSU9OX0JBREdFX1JFQUQiLCJQRVJNSVNTSU9OX1BST0pFQ1RfUkVBRCIsIlBFUk1JU1NJT05fVVNFUk1HTVRfREVMRVRFIiwiUEVSTUlTU0lPTl9DTEFJTV9SRUFEIiwiUEVSTUlTU0lPTl9UQUdfUkVBRCIsIlBFUk1JU1NJT05fUkVMRUFTRV9DUkVBVEUiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9ERUxFVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfUkVBRCIsIlBFUk1JU1NJT05fQUNUSVZJVFlTVFJFQU1fUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9SRUFEIiwiUEVSTUlTU0lPTl9DTEFJTV9VUERBVEUiLCJQRVJNSVNTSU9OX1VTRVJNR01UX1VQREFURSIsIlBFUk1JU1NJT05fS1VET19SRUFEIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9SRUFEIiwiUEVSTUlTU0lPTl9TQ0FOX0RFTEVURSIsIlBFUk1JU1NJT05fVlVMTkVSQUJJTElUWV9SRUFEIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fQ1JFQVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9DUkVBVEUiLCJQRVJNSVNTSU9OX1BST0pFQ1RfTElTVCIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX1JFQUQiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfREVMRVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9VUERBVEUiLCJQRVJNSVNTSU9OX1NDQU5fQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fUkVBRCIsIlBFUk1JU1NJT05fQVNTRVRfUkVGRVJFTkNFX0RFTEVURSIsIlBFUk1JU1NJT05fUE9MSUNZX1JVTEVfREVMRVRFIiwiUEVSTUlTU0lPTl9MSUNFTlNFX1VQREFURSIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX0NSRUFURSIsIlBFUk1JU1NJT05fS1VET19ERUxFVEUiLCJQRVJNSVNTSU9OX0JPTV9SRUFEIiwiUEVSTUlTU0lPTl9LVURPX0NSRUFURSIsIlBFUk1JU1NJT05fUkVMRUFTRV9SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX0NSRUFURSIsIlBFUk1JU1NJT05fVEVBTU1FTUJFUl9SRUFEIiwiUEVSTUlTU0lPTl9VU0VSTUdNVF9SRUFEIiwiUEVSTUlTU0lPTl9SRVZJRVdfUkVBRCIsIlBFUk1JU1NJT05fVVJMTElOS19SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX1NFQVJDSCJdLCJqdGkiOiI3ZmJlMGI2Ni01ODAzLTQxMzgtOGZkOS00NzE5OTZmNDgyN2UiLCJjbGllbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtMDAwMC0wMDAwMDAwMDAwMDEifQ.TFCqJ4Auy6QL4Vz_nzMWJG6hzngKBLYkZXZOryoZp2g',
        }

        headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'X-CSRF-TOKEN': '4d0f5299-c5c8-46f0-a982-fcdf41ece505',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Accept': '*/*',
            'Referer': 'https://blackduck-hub.mellanox.com/api.html',
            'Connection': 'keep-alive',
        }
        headers.update({'X-CSRF-TOKEN':self.csrf})

        response = self.aSeesion.get(url=url,
                                headers=headers, cookies=cookies, verify=False)
        time.sleep(15)

        if response.status_code == 200:
            time.sleep(10)
            try:
                logging.debug("converting the file into StringIO...")
                fp = StringIO.StringIO(response.content)
            except Exception as e:
                logging.error("Exception in creating zipfile from StringIO")
                print(e)
                sys.exit(1)
            try:
                logging.info("Creating directory with folder under : " + os.getcwd())
                zfp = zipfile.ZipFile(fp, "r")
                zfp.extractall(path=os.getcwd())
            except Exception as e:
                logging.error("Exception  with extracting the file into " + os.getcwd())
                sys.exit(1)
            # Changing directory to getcwd + projectname
            try:
                logging.debug("Changing directory to getcwd + project name")
                os.chdir(self.project_name)
            except Exception as e:
                logging.error("Exception in Changing directory")
            try:
                with zipfile.ZipFile(os.getcwd() + self.project_name,'r') as zip_ref:
                    zip_ref.extractall(os.getcwd())
                    #TODO- what is the name of the directory created ?
                    #self.blackduck_files_path =
            except Exception as e:
                logging.error("Exception in exctrating files of zip_ref")
                sys.exit(1)
            logging.info("blackduck report files are located under " + str(os.getcwd()))

    def urlCompose(self, path=''):
        return self.URL + '/' + path

    def authenticate(self, username, password):
        # Username and password will be sent in body of post request

        cookies = {
            '_ga': 'GA1.2.670127896.1502020316',
            'optimizelyEndUserId': 'oeu1515931479510r0.043819977420917144',
            '__utma': '194694719.670127896.1502020316.1534161606.1534161606.1',
            '__utmz': '194694719.1534161606.1.1.utmcsr=wikinox.mellanox.com|utmccn=(referral)|utmcmd=referral|utmcct=/display/IT/KVM%20installation%20and%20SRIOV%20cx3',
            'ls': 'gseo',
            'sub': 'true',
            'username': 'Arielwe',
            'TS01e51510': '018428d7a4e2f0813dfd9b9fc47d3a8467d58d92793e485271776b63818dd992fe494549bde69d1cf2a387d03982dfb8e678def8519ceaecdca4b5fb7ba84c768f4ab80e62b0e624c861a97febbca32f29a9ab7283',
        }

        headers = {
            'Origin': 'https://blackduck-hub.mellanox.com',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': '*/*',
            'Referer': 'https://blackduck-hub.mellanox.com/',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }

        data = {
            'j_username': 'arielwe',
            'j_password': '12345678'
        }

        response =self.aSeesion.post('https://blackduck-hub.mellanox.com/j_spring_security_check', headers=headers,
                                 cookies=cookies, data=data, verify=False)
        
        # check for Success
        if response.ok:
            self.csrf = response.headers['x-csrf-token']
            return 1
        else:
            print
            "Error in authentication to hub server"
            return 0

    def createCSVReport(self):
        versionId = self.verison_id
        url = 'https://blackduck-hub.mellanox.com/api/v1/versions/version_id/reports'
        cookies = {
            '_ga': 'GA1.2.670127896.1502020316',
            'optimizelyEndUserId': 'oeu1515931479510r0.043819977420917144',
            '__utma': '194694719.670127896.1502020316.1534161606.1534161606.1',
            '__utmz': '194694719.1534161606.1.1.utmcsr=wikinox.mellanox.com|utmccn=(referral)|utmcmd=referral|utmcct=/display/IT/KVM%20installation%20and%20SRIOV%20cx3',
            'ls': 'gseo',
            'sub': 'true',
            'username': 'Arielwe',
            '_gid': 'GA1.2.987609298.1546936852',
            'AUTHORIZATION_BEARER': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodWJfaWQiOiI0ZmU4ZWU3OS1jMjEyLTRiODMtOGY0Yi1hZDQ5Yzc2N2QyNjYiLCJ1c2VyX25hbWUiOiJhcmllbHdlIiwic2NvcGUiOlsid3JpdGUiLCJyZWFkIiwiY2xpZW50X21hbmFnZW1lbnQiXSwiY3NyZiI6InozT2ZoYW94dGFQSzRxQkdPbkMwU2xoMEZnZWRVYkovVXo2TFB4WUh4RXVLRUpVWHJsbnZxRmxjb2RiZ0VoRzAiLCJleHAiOjE1NDY5NTYwNDEsImF1dGhvcml0aWVzIjpbIlBFUk1JU1NJT05fQ0xBSU1fREVMRVRFIiwiUEVSTUlTU0lPTl9DT05GSUdfQ09NTU9OIiwiUEVSTUlTU0lPTl9SRUxFQVNFX0xJU1QiLCJQRVJNSVNTSU9OX0JBREdFX1JFQUQiLCJQRVJNSVNTSU9OX1BST0pFQ1RfUkVBRCIsIlBFUk1JU1NJT05fVVNFUk1HTVRfREVMRVRFIiwiUEVSTUlTU0lPTl9DTEFJTV9SRUFEIiwiUEVSTUlTU0lPTl9UQUdfUkVBRCIsIlBFUk1JU1NJT05fUkVMRUFTRV9DUkVBVEUiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9ERUxFVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfUkVBRCIsIlBFUk1JU1NJT05fQUNUSVZJVFlTVFJFQU1fUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9SRUFEIiwiUEVSTUlTU0lPTl9DTEFJTV9VUERBVEUiLCJQRVJNSVNTSU9OX1VTRVJNR01UX1VQREFURSIsIlBFUk1JU1NJT05fS1VET19SRUFEIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9SRUFEIiwiUEVSTUlTU0lPTl9TQ0FOX0RFTEVURSIsIlBFUk1JU1NJT05fVlVMTkVSQUJJTElUWV9SRUFEIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fQ1JFQVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9DUkVBVEUiLCJQRVJNSVNTSU9OX1BST0pFQ1RfTElTVCIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX1JFQUQiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfREVMRVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9VUERBVEUiLCJQRVJNSVNTSU9OX1NDQU5fQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fUkVBRCIsIlBFUk1JU1NJT05fQVNTRVRfUkVGRVJFTkNFX0RFTEVURSIsIlBFUk1JU1NJT05fUE9MSUNZX1JVTEVfREVMRVRFIiwiUEVSTUlTU0lPTl9MSUNFTlNFX1VQREFURSIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX0NSRUFURSIsIlBFUk1JU1NJT05fS1VET19ERUxFVEUiLCJQRVJNSVNTSU9OX0JPTV9SRUFEIiwiUEVSTUlTU0lPTl9LVURPX0NSRUFURSIsIlBFUk1JU1NJT05fUkVMRUFTRV9SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX0NSRUFURSIsIlBFUk1JU1NJT05fVEVBTU1FTUJFUl9SRUFEIiwiUEVSTUlTU0lPTl9VU0VSTUdNVF9SRUFEIiwiUEVSTUlTU0lPTl9SRVZJRVdfUkVBRCIsIlBFUk1JU1NJT05fVVJMTElOS19SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX1NFQVJDSCJdLCJqdGkiOiI4Njk4MTQzNy00NDQxLTQ1MDItYTcwYy0wMDA4NWQxOTEwNjciLCJjbGllbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtMDAwMC0wMDAwMDAwMDAwMDEifQ.zzmM5r6m8RFHiyOdP8w1rbgd-SY4biL584e2S6-rVAQ',
        }

        headers = {
            'Origin': 'https://blackduck-hub.mellanox.com',
            'Accept-Encoding': 'gzip, deflate, br',
            'X-CSRF-TOKEN': 'd1c10aa4-6ca5-498c-8718-da52010ed2df',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': 'https://blackduck-hub.mellanox.com/ui/versions/id:version_id/view:reports',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }
        headers.update({'X-CSRF-TOKEN': self.csrf})

        # Changing the version id in the correct places

        data = '{"categories":["VERSION","CODE_LOCATIONS","COMPONENTS","SECURITY","FILES"],"versionId":"version_id","reportType":"VERSION","reportFormat":"CSV"}'

        data = data.replace("version_id", versionId)
        url = url.replace("version_id", versionId)

        for key, value in headers.items():
            if "version_id" in str(value):
                headers[key] = str(value).replace("version_id", versionId)

        try:
            logging.info("trying to createCSV Report")
            response = self.aSeesion.post(
                url=url,
                headers=headers, cookies=cookies, data=data, verify=False)
        except Exception as e:
            print ("Exception during REST API for CreateCSVReport...")

        if response.status_code == 200:
            print ("Rest API for CreateCSVReport successfully...")
            print ("Retreving ReportID for response content")
            reportid = str(response.content).split(':')[1].split("\"")[1]
            print ("ReportID is " + str(reportid))
            self.report_id = reportid

        else:
            print ("CreateCSVReport failed with REST API... status code is: " + str(response.status_code))
            sys.exit(1)
    def getVulnerabilitySummary(self):

        #TODO - delete
        self.verison_id='2a583e14-89c3-47a8-a2b6-e3d0a77d02ca'

        url = 'https://blackduck-hub.mellanox.com/api/v1/releases/version_id/bom-risk-profile'.replace("version_id",self.verison_id)

        cookies = {
            '_ga': 'GA1.2.670127896.1502020316',
            'optimizelyEndUserId': 'oeu1515931479510r0.043819977420917144',
            '__utma': '194694719.670127896.1502020316.1534161606.1534161606.1',
            '__utmz': '194694719.1534161606.1.1.utmcsr=wikinox.mellanox.com|utmccn=(referral)|utmcmd=referral|utmcct=/display/IT/KVM%20installation%20and%20SRIOV%20cx3',
            'ls': 'gseo',
            'sub': 'true',
            'username': 'Arielwe',
            'TS01e51510': '018428d7a4e2f0813dfd9b9fc47d3a8467d58d92793e485271776b63818dd992fe494549bde69d1cf2a387d03982dfb8e678def8519ceaecdca4b5fb7ba84c768f4ab80e62b0e624c861a97febbca32f29a9ab7283',
            'AUTHORIZATION_BEARER': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodWJfaWQiOiI0ZmU4ZWU3OS1jMjEyLTRiODMtOGY0Yi1hZDQ5Yzc2N2QyNjYiLCJ1c2VyX25hbWUiOiJhcmllbHdlIiwic2NvcGUiOlsid3JpdGUiLCJyZWFkIiwiY2xpZW50X21hbmFnZW1lbnQiXSwiY3NyZiI6IlJHVzdRTkFqQ3ZYSkRLUG8zVWxieE8rbS9mRTE1V3RPYkREU1VHWkZsZUFzZ1lqV2dDRURIeTVuaDdBdWFpeHEiLCJleHAiOjE1NDc3Mzg2MTYsImF1dGhvcml0aWVzIjpbIlBFUk1JU1NJT05fQ0xBSU1fREVMRVRFIiwiUEVSTUlTU0lPTl9DT05GSUdfQ09NTU9OIiwiUEVSTUlTU0lPTl9SRUxFQVNFX0xJU1QiLCJQRVJNSVNTSU9OX0JBREdFX1JFQUQiLCJQRVJNSVNTSU9OX1BST0pFQ1RfUkVBRCIsIlBFUk1JU1NJT05fVVNFUk1HTVRfREVMRVRFIiwiUEVSTUlTU0lPTl9DTEFJTV9SRUFEIiwiUEVSTUlTU0lPTl9UQUdfUkVBRCIsIlBFUk1JU1NJT05fUkVMRUFTRV9DUkVBVEUiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9ERUxFVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfUkVBRCIsIlBFUk1JU1NJT05fQUNUSVZJVFlTVFJFQU1fUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9SRUFEIiwiUEVSTUlTU0lPTl9DTEFJTV9VUERBVEUiLCJQRVJNSVNTSU9OX1VTRVJNR01UX1VQREFURSIsIlBFUk1JU1NJT05fS1VET19SRUFEIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9SRUFEIiwiUEVSTUlTU0lPTl9TQ0FOX0RFTEVURSIsIlBFUk1JU1NJT05fVlVMTkVSQUJJTElUWV9SRUFEIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfUkVBRCIsIlBFUk1JU1NJT05fU0NBTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9BU1NFVF9SRUZFUkVOQ0VfQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fQ1JFQVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9DUkVBVEUiLCJQRVJNSVNTSU9OX1BST0pFQ1RfTElTVCIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX1JFQUQiLCJQRVJNSVNTSU9OX0NPREVMT0NBVElPTl9VUERBVEUiLCJQRVJNSVNTSU9OX0xJQ0VOU0VfREVMRVRFIiwiUEVSTUlTU0lPTl9QT0xJQ1lfUlVMRV9VUERBVEUiLCJQRVJNSVNTSU9OX1NDQU5fQ1JFQVRFIiwiUEVSTUlTU0lPTl9XQVRDSElURU1fUkVBRCIsIlBFUk1JU1NJT05fQVNTRVRfUkVGRVJFTkNFX0RFTEVURSIsIlBFUk1JU1NJT05fUE9MSUNZX1JVTEVfREVMRVRFIiwiUEVSTUlTU0lPTl9MSUNFTlNFX1VQREFURSIsIlBFUk1JU1NJT05fQ09ERUxPQ0FUSU9OX0NSRUFURSIsIlBFUk1JU1NJT05fS1VET19ERUxFVEUiLCJQRVJNSVNTSU9OX0JPTV9SRUFEIiwiUEVSTUlTU0lPTl9LVURPX0NSRUFURSIsIlBFUk1JU1NJT05fUkVMRUFTRV9SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX0NSRUFURSIsIlBFUk1JU1NJT05fVEVBTU1FTUJFUl9SRUFEIiwiUEVSTUlTU0lPTl9VU0VSTUdNVF9SRUFEIiwiUEVSTUlTU0lPTl9SRVZJRVdfUkVBRCIsIlBFUk1JU1NJT05fVVJMTElOS19SRUFEIiwiUEVSTUlTU0lPTl9QUk9KRUNUX1NFQVJDSCJdLCJqdGkiOiIwOGVmMWNhZS1iZGVhLTQ2NWQtOTVjOS0zYzk3NzljZTU0NTgiLCJjbGllbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtMDAwMC0wMDAwMDAwMDAwMDEifQ.EiAaBb8xnrKXlHmNY_At32BQKdsaGAkrryijUuyGQTs',
        }

        headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': 'https://blackduck-hub.mellanox.com/ui/versions/id:95199fe1-a4c0-4d60-ac53-be448ad2bd8c/view:bom',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }

        response = self.aSeesion.get(
            url=url,
            headers=headers, cookies=cookies, verify=False)

        if response.ok:
            import json
            logging.debug("REST API for getting vulnerability summary ended successfully")
            content_str = str(response.content,'utf-8')
            content_json = json.loads(content_str)
            return content_json

        else:
            logging.error("getting vulnerability summary failed!...\nexiting!")
            sys.exit(1)



    def createPlots(self,content_json):
        categories = ['OPERATIONAL', 'VERSION', 'ACTIVITY', 'LICENSE', 'VULNERABILITY']
        risk_levels = ['HIGH', 'MEDIUM', 'LOW', 'OK', 'UNKNOWN']

        if os.path.exists('graphs'):
            shutil.rmtree("graphs")

        os.mkdir('graphs')

        counter = 0
        # feching information from json object:
        for caregory in categories:
            values = []
            for risk_level in risk_levels:
                value = content_json['categories'][caregory][risk_level]
                values.append(value)

            self.createPlot(risk_levels, values, categories[counter])
            counter+=1

    def createPlot(self, labels, values, plotname):

        logging.info("Create plot for : plotname")
        recipe =[]
        for value,label in zip(values,labels):
             my_str = str(value) + ' ' +  str(label)
             recipe.append(my_str)
        fig, ax = plt.subplots(figsize=(6, 3), subplot_kw=dict(aspect="equal"))



        # recipe = ["225 g flour",
        #           "90 g sugar",
        #           "1 egg",
        #           "60 g butter",
        #           "100 ml milk",
        #           "1/2 package of yeast"]

        data = values

        wedges, texts = ax.pie(data, wedgeprops=dict(width=0.5), startangle=-40)

        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        kw = dict(xycoords='data', textcoords='data', arrowprops=dict(arrowstyle="-"),
                  bbox=bbox_props, zorder=0, va="center")

        for i, p in enumerate(wedges):
            ang = (p.theta2 - p.theta1) / 2. + p.theta1
            y = np.sin(np.deg2rad(ang))
            x = np.cos(np.deg2rad(ang))
            horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
            connectionstyle = "angle,angleA=0,angleB={}".format(ang)
            kw["arrowprops"].update({"connectionstyle": connectionstyle})
            ax.annotate(recipe[i], xy=(x, y), xytext=(1.35 * np.sign(x), 1.4 * y),
                        horizontalalignment=horizontalalignment, **kw)

        ax.set_title(plotname + " Risk")
        #ax.set_color_cycle(['red', 'orange', 'green', 'pink', 'yellow'])
        plt.savefig(os.getcwd() + os.sep + "graphs" + os.sep + plotname + ".png", dpi=80)
        logging.info("plot was saved!")
        logging.info("Create plot for : plotname is done")


    def create_email(self):
        pass

    def send_email_to_recipient(self):
        #Create plots for email body:
        logging.info("Trying to create vulnerabilty summary")
        vulnerabily_json = self.getVulnerabilitySummary()
        self.createPlots(vulnerabily_json)
        #resizing the pictures before sending them via email.
        logging.info("Resize the pictures to 400X400 pixels")
        #self.resize_images()
        email_user = 'memory.tester1234@gmail.com'
        email_password = '2wsx@WSX'
        subject = 'Blackduck Hub results for ' + self.project_name

        msg = EmailMessage()
        msg.set_content('This is a plain text body.')
        msg['From'] = email_user
        msg['To'] = ", ".join(self.recepint_list)
        msg['Subject'] = subject
        final_image_string = ""
        # now create a Content-ID for the image
        img_cid_list = []
        for plotname in os.listdir(self.plots_path):
            image_cid = make_msgid(domain='xyz.com')
            img_cid_list.append(image_cid)
            tmp_string = """<img src="cid:{image_cid}">""".format(image_cid=image_cid[1:-1])
            final_image_string = final_image_string + tmp_string

        body = """\
        <html>
            <body>
                 <p>
                           Hi there, here are the results for blackduck hub.<br> \
                            <b>Security Risk -</b> uncovers security vulnerabilities contained within components by referencing data  \
                            from the National Vulnerability Database (NVD)<br> \
                            <b>Operational Risk -</b> evaluates, using a risk score algorithm, if components meet your technical and architectural standards 
                           </p> 
                <IMAGES>
            </body>
        </html>
        """
        body = body.replace("<IMAGES>", final_image_string)
        # set an alternative html body
        msg.add_alternative(body, subtype='html')
        # image_cid looks like <long.random.number@xyz.com>
        # to use it as the img src, we don't need `<` or `>`
        # so we use [1:-1] to strip them off
        # trying to attach the graphs to email body
        for plotname in os.listdir(self.plots_path):
                picture_path = self.plots_path + os.sep + plotname
                with open(picture_path, 'rb') as img:
                    image_cid = img_cid_list.pop()
                    # know the Content-Type of the image
                    maintype, subtype = mimetypes.guess_type(img.name)[0].split('/')

                    # attach it
                    msg.get_payload()[1].add_related(img.read(),
                                                 maintype=maintype,
                                                 subtype=subtype,
                                                 cid=image_cid)




        directory = '/root/PycharmProjects/bd/ufm_appliance_orig_rpms_nodups_1'
        attached_files = os.listdir(directory)
        for filename in attached_files:
            logging.info("Sending last result for recepint list")
            try:
                full_path = directory + os.sep + filename
                attachment = open(full_path, 'rb')

                part = MIMEBase('application', 'octet-stream')
                part.set_payload((attachment).read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', "attachment; filename= " + filename)
                msg.attach(part)
                text = msg.as_string()
            except Exception as e:
                print("exception in sending graphs via email\n" + str(e))
            logging.info("All files were added as attachments to email")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email_user, email_password)
        if attached_files:
            server.sendmail(email_user, self.recepint_list , text)
        server.quit()

    def resize_images(self):
        for plotname in os.listdir(self.plots_path):
            try:
                plot_path = self.plots_path + os.sep + plotname
                image = Image.open(plot_path,'r')
                cover = resizeimage.resize_cover(image, [800, 800])
                new_name = str(plot_path).split('.')[0] + '_resize.png'
                cover.save(new_name, image.format)
                os.remove(plot_path)
            except Exception as e:
                logging.error("Exception with resize the picture" + str(e))
                sys.exit(1)

 
def main():

    #TODO ArgPasre
    parser = argparse.ArgumentParser(description='simple usage: --project NEO --username Arielwe \
    --password 12345678 --file /qa/qa/security/neo/neo-2.3.0-91.el7.tar.gz --debug yes')
    parser.add_argument('--project',choices=['UFM','UFMAPL','NEO','MFT','HPCX'] , dest='project', help='select a project from list')
    parser.add_argument('--username', help='set username for blackduck',dest='username', required=True)
    parser.add_argument('--password', help='set password for blackduck',dest='password', required=True)
    parser.add_argument('--file', help='file or directory to scan',dest='file', required=True)
    parser.add_argument('--debug', dest='debug', help='change to debug mode')

    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(filename='blackduck.log',
                        level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filemode='w')

    logging.info("Start Script...")

    try:
        logging.debug("Trying to create Bluackduck Class")
        bd = Blackhub(username=args.username,password=args.password,recepient_list='arielwe@mellanox.com,weiser.ariel@gmail.com',release=str(args.file).split('/').pop(), \
                     project_name=args.project,project_file_path=args.file)
    except Exception as e:
        logging.error("Blackduck hub class was failed")
        sys.exit(1)

    json = bd.getVulnerabilitySummary()
    bd.createPlots(json)
    bd.send_email_to_recipient()

    # bd.createPlot("example_plot",values=[1,2,3,4])
    # logging.debug("Calling Scan from Main")
    # bd.scan()
    # logging.debug("Scan function is completed successfully")
    # logging.debug("Calling setVersionID from main")
    # bd.setVersionId()
    # logging.info("Sleeping for one hour while scan is running in background....\nYou can take Coffee meanwhile:)")
    # time.sleep(60*60)
    # logging.info("sleep is done.")
    # logging.debug("Calling CreateCSVReport from main")
    # bd.createCSVReport()
    # logging.debug("Calling DownloadCSV report from main")
    # bd.downloadCSVReport()
    # logging.info("Sending result to recepient list")
    # bd.send_email_to_recipient()




if __name__ == "__main__":
    main()
