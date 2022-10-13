#!/usr/bin/python

import argparse, hashlib, hmac, json, logging, os, random, shutil, struct, sys, zipfile
import urllib
from io import BytesIO
from logging.handlers import SMTPHandler
from datetime import datetime, timedelta

EXIT_CODES = {
    'dolphin_mac': 1,
    'incorrect_mac': 2,
    'incorrect_region': 3
}

TEMPLATES = {
    'U':"templateU.bin",
    'E':"templateE.bin",
    'J':"templateJ.bin",
    'K':"templateK.bin",
}

BUNDLEBASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bundle')
COUNTRY_REGIONS = dict([l.split(" ") for l in open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'country_regions.txt')).read().split("\n") if l])


def main(mac_string, region, output, do_zip, use_bundle, verify_mac):
    sep = '°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°'
    print(sep)
    print(

        '''          _        _   _           ___            _     ___ _    ___ 
         | |   ___| |_| |_ ___ _ _| _ ) ___ _ __ | |__ / __| |  |_ _|
         | |__/ -_)  _|  _/ -_) '_| _ \\/ _ \\ '  \\| '_ \\ (__| |__ | | 
         |____\\___|\\__|\\__\\___|_| |___/\\___/_|_|_|_.__/\\___|____|___|
         '''
        )
    print('Adapted by jack')
    print('License: GPLv3+SNEED')
    print(sep)

    try:
        mac_int_array = []
        for i in range(0, 12, 2):
            mac_int_array.append(int(mac_string[i:i + 2], 16))
        mac = bytes(mac_int_array)
    except Exception as e:
        print(e)
        printn("Can not parse MAC")
        sys.exit(EXIT_CODES['incorrect_mac'])
    region = region.upper()
    if region not in TEMPLATES.keys():
        print("Invalid region. Valid regions: U, E, J, K.")
        sys.exit(EXIT_CODES['incorrect_region'])

    OUI_LIST = [bytes.fromhex(i) for i in open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'oui_list.txt')).read().split("\n") if len(i) == 6]
    dt = datetime.utcnow() - timedelta(1)
    delta = (dt - datetime(2000, 1, 1))
    timestamp = delta.days * 86400 + delta.seconds


    if mac == b"\x00\x17\xab\x99\x99\x99":
        print(f'Derp MAC {mac.hex()} at {timestamp} ver {region} bundle {use_bundle}')
        print("If you're using Dolphin, try File->Open instead ;-).")
        sys.exit(EXIT_CODES['dolphin_mac'])

    if verify_mac and not any([mac.startswith(i) for i in OUI_LIST]):
        print(f'Bad MAC {mac.hex()} at {timestamp} ver {region} bundle {use_bundle}')
        print("The exploit will only work if you enter your Wii's MAC address.")
        sys.exit(EXIT_CODES['incorrect_mac'])

    key = hashlib.sha1(mac + b"\x75\x79\x79").digest()
    blob = bytearray(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'region_templates', 'template' + region + '.bin'), 'rb').read())
    blob[0x08:0x10] = key[:8]
    blob[0xb0:0xc4] = bytes(20)
    blob[0x7c:0x80] = struct.pack(">I", timestamp)
    blob[0x80:0x8a] = (b"%010d" % timestamp)
    blob[0xb0:0xc4] = hmac.new(key[8:], bytes(blob), hashlib.sha1).digest()

    #path = f'private/wii/title/HAEA/{key[:4].hex().upper()}/{key[4:8].hex().upper()}/{dt.year:04}/{dt.month-1:02}/{dt.day:02}/{dt.hour:02}/{dt.minute:02}/HABA_#1/txt/{hex(timestamp).upper()[2:]:08}.000'
    path = os.path.join('private', 'wii', 'title', 'HAEA', key[:4].hex().upper(), key[4:8].hex().upper(), f'{dt.year:04}', f'{dt.month-1:02}', f'{dt.day:02}', f'{dt.hour:02}', f'{dt.minute:02}', 'HABA_#1', 'txt')
    blob_path = os.path.join(path, f'{hex(timestamp).upper()[2:]:08}.000')

    BUNDLE = [(name, os.path.join(BUNDLEBASE, name)) for name in os.listdir(BUNDLEBASE) if not name.startswith(".")]

    if do_zip:
        if not output.endswith('.zip'):
            output += '.zip'
        zip = zipfile.ZipFile(output, 'w')
        zip.writestr(blob_path, blob)
        if use_bundle:
            for name, f_path in BUNDLE:
                zip.write(f_path, name)
        zip.close()
    else:
        os.makedirs(os.path.join(output, path), exist_ok=True)
        open(os.path.join(output, blob_path), 'wb').write(blob)
        if use_bundle:
            for name, f_path in BUNDLE:
                shutil.copyfile(f_path, os.path.join(output, name))


    print(f'LetterBombed {mac.hex()} at {timestamp} ver {region} bundle {use_bundle}')

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(prog='letterbomb', description='Creates a letterbomb zip. Works only on Wii 4.3 firmware. Based on https://github.com/fail0verflow/letterbomb. License: LGPLv3+SNEED.\nExit codes:\n- Dolphin MAC: 1\n- Incorrect MAC: 2\n- Incorrect region: 3')
    arg_parser.add_argument('--mac', help='Wii MAC address', required=True)
    arg_parser.add_argument('--region', help='Wii region. Available regions: U, E, J, K (USA, Europe, Japan, Korea).', required=True)
    arg_parser.add_argument('--output', nargs='?', default='LetterBomb', help='Output name/folder. LetterBomb by default.')
    arg_parser.add_argument('--zip', action='store_true', help='Save result as zip, false by default.')
    arg_parser.add_argument('--nobundle', action='store_false', help='Don\'t bundle, false by default.')
    arg_parser.add_argument('--nomacverif', action='store_false', help='Skip MAC OUI validation, false by default.')
    args = arg_parser.parse_args()

    main(args.mac, args.region, args.output, args.zip, args.nobundle, args.nomacverif)
