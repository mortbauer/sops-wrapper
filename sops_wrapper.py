import os
import re
import argparse
import logging
import subprocess

from ruamel.yaml import YAML

logger = logging.getLogger(__name__)

yaml = YAML(typ='safe')

def is_encrypted(path):
    """ very basic check, would be solved with https://github.com/mozilla/sops/issues/460 """
    comp_process = subprocess.run(
        ['grep','sops',path,'-l'],
        stdout=subprocess.PIPE,
        encoding='utf-8',
    )
    res = (comp_process.stdout.strip() == path)
    return res

def get_sops_config():
    with open('.sops.yaml','r') as sopsf:
        conf = yaml.load(sopsf)
    return conf

def get_matching_files():
    for root,dirs,files in os.walk('.'):
        for filepath in files:
            if filepath.endswith('.sops.yaml'):
                continue
            yield os.path.join(root,filepath)

def get_staged_files():
    comp_process = subprocess.run(
        ['git','diff','--name-only','--cached'],
        stdout=subprocess.PIPE,
        encoding='utf-8',
    )
    results = []
    # filter out deleted files
    for path in comp_process.stdout.splitlines():
        if os.path.exists(path):
            results.append(path)
    return results

def get_tracked_files():
    comp_process = subprocess.run(
        ['git','ls-tree','-r','HEAD','--name-only'],
        stdout=subprocess.PIPE,
        encoding='utf-8',
    )
    return comp_process.stdout.splitlines()



def make_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    setup_encrypt(subparsers.add_parser('encrypt', help='encrypt all staged files'))
    setup_decrypt(subparsers.add_parser('decrypt', help='decrypt all tracked files'))
    parser.add_argument('-l','--log-level',default='WARNING')
    return parser

def setup_common_parser(parser):
    parser.add_argument('-d','--dry-run',action='store_true',help='only print actions without doing them')
    parser.add_argument('-g','--use-git',action='store_true',help='use git for getting')

def setup_encrypt(parser):
    parser.set_defaults(command=encrypt)
    setup_common_parser(parser)

def setup_decrypt(parser):
    parser.set_defaults(command=decrypt)
    setup_common_parser(parser)

def needs_encryption(encrypted_regex,path):
    pattern = re.compile(encrypted_regex)
    with open(path,'r') as _file:
        for line in _file:
            if pattern.search(line):
                logger.debug('Matching pattern %s for line %s for %s',pattern,line,path)
                return True
    return False

def encrypt(dry_run=False,use_git=False):
    conf = get_sops_config()
    patterns = {}
    for rule in conf.get('creation_rules',[]):
        patterns[re.compile(rule.get('path_regex'))] = rule
    paths = []
    if use_git:
        iterator = get_staged_files()
    else:
        iterator = get_matching_files()
    errors = []
    for path in iterator:
        rule = None
        for pattern in patterns:
            if pattern.search(path):
                rule = patterns[pattern]
        if rule is not None:
            encrypted_regex = rule.get('encrypted_regex','.*')
            if is_encrypted(path):
                logger.info('%s already encrypted with sops',path)
            elif not needs_encryption(encrypted_regex,path):
                logger.log(5,'%s not matching any encrypted_regex',path)
            else:
                if not dry_run:
                    try:
                        subprocess.run(['sops','--in-place','--encrypt',path],check=True)
                    except Exception as err:
                        errors.append((path,err))
                    paths.append(path)
                    # logger.info('encrypted %s with sops',path)
                else:
                    print(f'would encrypt {path}')
        else:
            logger.log(5,'no match for %s',path)
    if errors:
        raise Exception('found %s'%errors)
    # if paths and not dry_run:
        # no add the changed files to the staging area again
        # subprocess.run(['git','add']+paths)

def decrypt(dry_run=False,use_git=False):
    conf = get_sops_config()
    patterns = set()
    for rule in conf.get('creation_rules',[]):
        patterns.add('({})'.format(rule.get('path_regex')))
    pattern = re.compile('|'.join(patterns))
    if use_git:
        iterator = get_staged_files()
    else:
        iterator = get_matching_files()
    for path in iterator:
        if pattern.search(path):
            if is_encrypted(path):
                if not dry_run:
                    subprocess.run(['sops','--in-place','--decrypt',path],check=True)
                logger.info('decrypted %s with sops',path)
            else:
                logger.info('%s already decrypted',path)
        else:
            logger.debug('no match for %s',path)


def main():
    parser = make_parser()
    kwargs = vars(parser.parse_args())
    logging.basicConfig(level=kwargs.pop('log_level','info').upper())
    if 'command' not in kwargs:
        parser.print_help()
    else:
        command = kwargs.pop('command')
        command(**kwargs)

if __name__ == '__main__':
    main()
