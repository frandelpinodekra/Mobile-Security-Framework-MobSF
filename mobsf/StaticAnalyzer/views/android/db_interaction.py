# -*- coding: utf_8 -*-
import logging

from django.conf import settings
from django.db.models import QuerySet
import os
import secrets

import uuid

from mobsf.MobSF.utils import python_dict, python_list
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.models import MASAAnalysis

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad 
import base64
from .masa_results import MASA_NOT_ANALYSIS, MASA_ANALYSIS
"""Module holding the functions for the db."""


logger = logging.getLogger(__name__)
# create the cipher object
# cipher = AES.new(key, AES.MODE_CBC, iv) 

def getEncryptedData(plain): 
    return plain

def getEncrypteddData(plain): 

    return plain

    iv_bytes = secrets.token_hex(8)
    # iv_str = iv_bytes.hex()[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv) 

    padded_data = pad(plain.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    print('----------------------------------------------')
    print('iv: ' + str(iv))
    print('encrypted: ' + str(encrypted_data))
    print('base64: ' + str(base64.b64encode(encrypted_data).decode('utf-8')))
    print('----------------------------------------------')
    return base64.b64encode(encrypted_data).decode('utf-8')

    # if(type(plain) == dict):
    #     # Convert dictionary to string representation
    #     # data_str = str(plain).encode('utf-8')
        
    #     # Pad the data to the AES block size
    #     # padded_data = pad(data_str, AES.block_size)
        
    #     # Encrypt the padded data
    #     # encrypted_data = cipher.encrypt(padded_data)

    #     return plain

    # elif(type(plain) == list):
    #     # data_str = str(plain).encode('utf-8')
        
    #     # Pad the data to the AES block size
    #     # padded_data = pad(data_str, AES.block_size)
        
    #     # Encrypt the padded data
    #     # encrypted_data = cipher.encrypt(padded_data)
        
    #     return plain

    # elif (type(plain) == str):
    #     padded_data = pad(plain.encode('utf-8'), AES.block_size) 
        
    #     # Crea el cifrador y encripta los datos 
    #     encrypted_data = cipher.encrypt(padded_data)

    #     print('Encrypted data: ' + str(encrypted_data))
    #     print(base64.b64encode(encrypted_data).decode('utf-8'))
   
    # elif(type(plain) == bool):
    #     # # Convert boolean to string representation
    #     # data_str = str(plain).encode('utf-8')
        
    #     # # Pad the data to the AES block size
    #     # padded_data = pad(data_str, AES.block_size)
        
    #     # # Encrypt the padded data
    #     # encrypted_data = cipher.encrypt(padded_data)
    #     return plain
    
    # return base64.b64encode(encrypted_data).decode('utf-8')

# def getEncryptedData(plaintext): 
    
#     padded_data = pad(plaintext.encode('utf-8'), AES.block_size) 
#     encrypted_data = cipher.encrypt(padded_data) 
#     return base64.b64encode(encrypted_data).decode('utf-8') 

# def getEncryptedList(list): 
#     data = bytes(list)
#     padded_data = pad(list, AES.block_size) 
#     encrypted_data = cipher.encrypt(padded_data) 
#     return base64.b64encode(encrypted_data).decode('utf-8') 

# test_cases = ['DEKRA-STORAGE-2', 'DEKRA-CRYPTO-1', 'DEKRA-CRYPTO-3', 'DEKRA-PLATFORM-2', 'DEKRA-PLATFORM-3', 'DEKRA-NETWORK-1', 'DEKRA-NETWORK-2', 'DEKRA-NETWORK-3', 'DEKRA-CODE-1', 'DEKRA-CODE-2']
test_cases = ['DEKRA-STORAGE-2', 'DEKRA-CRYPTO-1', 'DEKRA-CRYPTO-3', 'DEKRA-PLATFORM-2', 'DEKRA-NETWORK-2', 'DEKRA-CODE-1', 'DEKRA-CODE-2']


def save_masa_analysis(masa_dic, md5):

    for test_name in test_cases:
        if test_name.lower() not in masa_dic:
            masa_dic[test_name.lower()] = MASA_NOT_ANALYSIS[test_name.lower()]
        
    
    values = {
            'ID': uuid.uuid4(),
            'APP_ID': md5,
            'STORAGE_2': masa_dic['dekra-storage-2'],
            'CRYPTO_1': masa_dic['dekra-crypto-1'],
            'CRYPTO_3': masa_dic['dekra-crypto-3'],
            'PLATFORM_2': masa_dic['dekra-platform-2'],
            'NETWORK_2': masa_dic['dekra-network-2'],
            'CODE_1': masa_dic['dekra-code-1'],
            'CODE_2': masa_dic['dekra-code-2']
    }

    MASAAnalysis.objects.using('tacs4masa').create(**values)

    return masa_dic
    


    

def get_context_from_db_entry(db_entry: QuerySet) -> dict:
    """Return the context for APK/ZIP from DB."""
    try:
        logger.info('Analysis is already Done. Fetching data from the DB...')
        context = {
            'version': settings.MOBSF_VER,
            'title': 'Static Analysis',
            'file_name': db_entry[0].FILE_NAME,
            'app_name': db_entry[0].APP_NAME,
            'app_type': db_entry[0].APP_TYPE,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'package_name': db_entry[0].PACKAGE_NAME,
            'main_activity': db_entry[0].MAIN_ACTIVITY,
            'exported_activities': db_entry[0].EXPORTED_ACTIVITIES,
            'browsable_activities': python_dict(db_entry[0].BROWSABLE_ACTIVITIES),
            'custom_schemes': python_dict(db_entry[0].CUSTOM_SCHEMES),
            'activities': python_list(db_entry[0].ACTIVITIES),
            'receivers': python_list(db_entry[0].RECEIVERS),
            'providers': python_list(db_entry[0].PROVIDERS),
            'services': python_list(db_entry[0].SERVICES),
            'libraries': python_list(db_entry[0].LIBRARIES),
            'target_sdk': db_entry[0].TARGET_SDK,
            'max_sdk': db_entry[0].MAX_SDK,
            'min_sdk': db_entry[0].MIN_SDK,
            'version_name': db_entry[0].VERSION_NAME,
            'version_code': db_entry[0].VERSION_CODE,
            'icon_hidden': db_entry[0].ICON_HIDDEN,
            'icon_found': db_entry[0].ICON_FOUND,
            'permissions': python_dict(db_entry[0].PERMISSIONS),
            'certificate_analysis': python_dict(
                db_entry[0].CERTIFICATE_ANALYSIS),
            'manifest_analysis': python_list(db_entry[0].MANIFEST_ANALYSIS),
            'network_security': python_list(db_entry[0].NETWORK_SECURITY),
            'binary_analysis': python_list(db_entry[0].BINARY_ANALYSIS),
            'file_analysis': python_list(db_entry[0].FILE_ANALYSIS),
            'android_api': python_dict(db_entry[0].ANDROID_API),
            'code_analysis': python_dict(db_entry[0].CODE_ANALYSIS),
            'niap_analysis': python_dict(db_entry[0].NIAP_ANALYSIS),
            'urls': python_list(db_entry[0].URLS),
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': python_list(db_entry[0].EMAILS),
            'strings': python_list(db_entry[0].STRINGS),
            'firebase_urls': python_list(db_entry[0].FIREBASE_URLS),
            'files': python_list(db_entry[0].FILES),
            'exported_count': python_dict(db_entry[0].EXPORTED_COUNT),
            'apkid': python_dict(db_entry[0].APKID),
            'quark': python_list(db_entry[0].QUARK),
            'trackers': python_dict(db_entry[0].TRACKERS),
            'playstore_details': python_dict(db_entry[0].PLAYSTORE_DETAILS),
            'secrets': python_list(db_entry[0].SECRETS),
        }
        return context
    except Exception:
        logger.exception('Fetching from DB')

def get_context_from_analysis(app_dic,
                              man_data_dic,
                              man_an_dic,
                              code_an_dic,
                              cert_dic,
                              bin_anal,
                              apk_id,
                              quark_report,
                              trackers) -> dict:
    """Get the context for APK/ZIP from analysis results."""
    try:
        context = {
            'title': 'Static Analysis',
            'version': settings.MOBSF_VER,
            'file_name': app_dic['app_name'],
            'app_name': app_dic['real_name'],
            'app_type': app_dic['zipped'],
            'size': app_dic['size'],
            'md5': app_dic['md5'],
            'sha1': app_dic['sha1'],
            'sha256': app_dic['sha256'],
            'package_name': man_data_dic['packagename'],
            'main_activity': man_data_dic['mainactivity'],
            'exported_activities': man_an_dic['exported_act'],
            'browsable_activities': man_an_dic['browsable_activities'],
            'custom_schemes': man_an_dic['custom_schemes'],
            'activities': man_data_dic['activities'],
            'receivers': man_data_dic['receivers'],
            'providers': man_data_dic['providers'],
            'services': man_data_dic['services'],
            'libraries': man_data_dic['libraries'],
            'target_sdk': man_data_dic['target_sdk'],
            'max_sdk': man_data_dic['max_sdk'],
            'min_sdk': man_data_dic['min_sdk'],
            'version_name': man_data_dic['androvername'],
            'version_code': man_data_dic['androver'],
            'icon_hidden': app_dic['icon_hidden'],
            'icon_found': app_dic['icon_found'],
            'certificate_analysis': cert_dic,
            'permissions': man_an_dic['permissions'],
            'manifest_analysis': man_an_dic['manifest_anal'],
            'network_security': man_an_dic['network_security'],
            'binary_analysis': bin_anal,
            'file_analysis': app_dic['certz'],
            'android_api': code_an_dic['api'],
            'code_analysis': code_an_dic['findings'],
            'niap_analysis': code_an_dic['niap'],
            'urls': code_an_dic['urls'],
            'domains': code_an_dic['domains'],
            'emails': code_an_dic['emails'],
            'strings': app_dic['strings'],
            'firebase_urls': code_an_dic['firebase'],
            'files': app_dic['files'],
            'exported_count': man_an_dic['exported_cnt'],
            'apkid': apk_id,
            'quark': quark_report,
            'trackers': trackers,
            'playstore_details': app_dic['playstore'],
            'secrets': app_dic['secrets'],
        }
        return context
    except Exception:
        logger.exception('Rendering to Template')

def save_or_update(update_type,
                   app_dic,
                   man_data_dic,
                   man_an_dic,
                   code_an_dic,
                   cert_dic,
                   bin_anal,
                   apk_id,
                   quark_report,
                   trackers) -> None:
    """Save/Update an APK/ZIP DB entry."""
    try:

        values = {
            'HASH': app_dic['hash'],
            'FILE_NAME': getEncrypteddData(app_dic['app_name']),
            'APP_NAME': getEncrypteddData(app_dic['real_name']),
            'APP_TYPE': getEncrypteddData(app_dic['zipped']),
            'SIZE': getEncrypteddData(app_dic['size']),
            'MD5': app_dic['md5'],
            'SHA1': getEncrypteddData(app_dic['sha1']),
            'SHA256': getEncrypteddData(app_dic['sha256']),
            'PACKAGE_NAME': getEncrypteddData(man_data_dic['packagename']),
            'MAIN_ACTIVITY': getEncrypteddData(man_data_dic['mainactivity']),
            'EXPORTED_ACTIVITIES': getEncryptedData(man_an_dic['exported_act']),
            'BROWSABLE_ACTIVITIES': getEncryptedData(man_an_dic['browsable_activities']),
            'CUSTOM_SCHEMES': getEncryptedData(man_an_dic['custom_schemes']),
            'ACTIVITIES': getEncryptedData(man_data_dic['activities']),
            'RECEIVERS': getEncryptedData(man_data_dic['receivers']),
            'PROVIDERS': getEncryptedData(man_data_dic['providers']),
            'SERVICES': getEncryptedData(man_data_dic['services']),
            'LIBRARIES': getEncryptedData(man_data_dic['libraries']),
            'TARGET_SDK': getEncryptedData(man_data_dic['target_sdk']),
            'MAX_SDK': getEncryptedData(man_data_dic['max_sdk']),
            'MIN_SDK': getEncryptedData(man_data_dic['min_sdk']),
            'VERSION_NAME': getEncryptedData(man_data_dic['androvername']),
            'VERSION_CODE': getEncryptedData(man_data_dic['androver']),
            'ICON_HIDDEN': getEncryptedData(app_dic['icon_hidden']),
            'ICON_FOUND': getEncryptedData(app_dic['icon_found']),
            'CERTIFICATE_ANALYSIS': getEncryptedData(cert_dic),
            'PERMISSIONS': getEncryptedData(man_an_dic['permissions']),
            'MANIFEST_ANALYSIS': getEncryptedData(man_an_dic['manifest_anal']),
            'BINARY_ANALYSIS': getEncryptedData(bin_anal),
            'FILE_ANALYSIS': getEncryptedData(app_dic['certz']),
            'ANDROID_API': getEncryptedData(code_an_dic['api']),
            'CODE_ANALYSIS': getEncryptedData(code_an_dic['findings']),
            'NIAP_ANALYSIS': getEncryptedData(code_an_dic['niap']),
            'URLS': getEncryptedData(code_an_dic['urls']),
            'DOMAINS': getEncryptedData(code_an_dic['domains']),
            'EMAILS': getEncryptedData(code_an_dic['emails']),
            'STRINGS': getEncryptedData(app_dic['strings']),
            'FIREBASE_URLS': getEncryptedData(code_an_dic['firebase']),
            'FILES': getEncryptedData(app_dic['files']),
            'EXPORTED_COUNT': getEncryptedData(man_an_dic['exported_cnt']),
            'APKID': getEncryptedData(apk_id),
            'QUARK': getEncryptedData(quark_report),
            'TRACKERS': getEncryptedData(trackers),
            'PLAYSTORE_DETAILS': getEncryptedData(app_dic['playstore']),
            'NETWORK_SECURITY': getEncryptedData(man_an_dic['network_security']),
            'SECRETS': getEncryptedData(app_dic['secrets']),
        }
        StaticAnalyzerAndroid.objects.create(**values)
        # if update_type == 'save':
        #     db_entry = StaticAnalyzerAndroid.objects.filter(
        #         MD5=app_dic['md5'])
        #     if not db_entry.exists():
        #         StaticAnalyzerAndroid.objects.create(**values)
        # else:
        #     StaticAnalyzerAndroid.objects.filter(
        #         MD5=app_dic['md5']).update(**values)
    except Exception:
        logger.exception('Updating DB')
    try:
        values = {
            'APP_NAME': getEncryptedData(app_dic['real_name']),
            'PACKAGE_NAME': getEncryptedData(man_data_dic['packagename']),
            'VERSION_NAME': getEncryptedData(man_data_dic['androvername']),
        }
        RecentScansDB.objects.filter(
            MD5=app_dic['md5']).update(**values)
    except Exception:
        logger.exception('Updating RecentScansDB')