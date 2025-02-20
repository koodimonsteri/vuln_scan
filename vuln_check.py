"""
Recursively loop all python files in a directory
Try to find very long lines with whitespace followed by some code and base64 encoded string.
Try to decode found b64
"""

import base64
import logging
from pathlib import Path
import re


logger = logging.getLogger(__name__)


"""
Regex matches whitespaces followed by arbitrary code
and after that it matches 10 or longer b64 string that is surrounded by single or double quotes 
"""
base64_regex = re.compile(r"\s*(?:[^\n]*?)['\"]([A-Za-z0-9+/=]{10,})['\"]")


def scan_line_for_vuln(line: str):
    if len(line) > 200:
        b64_match = base64_regex.search(line)
        if b64_match:
            logger.debug('Found b64 encoded string')
            b64 = b64_match.group(1).strip()
            logger.debug('b64: %s', b64)
            try:
                decoded = base64.b64decode(b64, validate=True)
            except Exception:
                decoded = b64
            return decoded
    return None


def scan_file_for_vuln(file_path: Path):

    with open(file_path, 'r', encoding='utf-8') as in_file:
        lines = in_file.readlines()

    for line in lines:
        if vuln := scan_line_for_vuln(line):
            logger.info('Found vulnerable line: %s', line)
            logger.info('Decoded code: %s', vuln)
            return line, vuln
    return None


def main():

    #file_path = Path(r'example_vuln.py') 
    #print(file_path)
    #scan_file_for_vuln(file_path)
    #exit(1)

    in_dir = Path(r'.venv/Lib/site-packages')
    vulnerable_files = {}
    for file in in_dir.rglob('*.py'):
        logger.info('Checking file: %s', file)
        res = scan_file_for_vuln(file)
        if not res:
            continue
        vulnerable_files[file] = res

    logger.info('Scan ready, found %s total suspicious files:', len(vulnerable_files))
    for f, res in vulnerable_files.items():
        logger.info('File: %s', f)
        line, vuln = res
        logger.info('Line: %s', line)
        logger.info('Code: %s', vuln)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()