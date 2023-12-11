import os
import shlex
import re
import argparse
import logging
import hashlib
import tempfile
import subprocess

from typing import Optional

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

def iter_files():
    for root,dirs,files in os.walk('.'):
        for filepath in files:
            if filepath.endswith('.sops.yaml'):
                continue
            yield os.path.join(root,filepath).lstrip('./')

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
    setup_gitignore(subparsers.add_parser('gitignore', help='make git ignore secret files'))
    parser.add_argument('-l','--log-level',default='INFO')
    return parser

def setup_common_parser(parser):
    parser.add_argument('-d','--dry-run',action='store_true',help='only print actions without doing them')
    parser.add_argument('-g','--use-git',action='store_true',help='use git for getting')
    parser.add_argument('-i','--in-place',action='store_true',help='encrypt/decrypt in place')
    parser.add_argument('-s','--suffix',default='.enc',help='suffix to append/remove when encrypting/decrypting')

def setup_encrypt(parser):
    parser.set_defaults(command=encrypt)
    parser.add_argument('--sops-args',default='')
    parser.add_argument('-p','--path-pattern',help='limit to these files')
    setup_common_parser(parser)

def setup_decrypt(parser):
    parser.set_defaults(command=decrypt)
    parser.add_argument('--sops-args',default='')
    parser.add_argument('-p','--path-pattern',help='limit to these files')
    setup_common_parser(parser)

def setup_gitignore(parser):
    parser.set_defaults(command=manage_gitignore)
    setup_common_parser(parser)

def needs_encryption(encrypted_regex,path):
    pattern = re.compile(encrypted_regex)
    try:
        with open(path,'r') as _file:
            for line in _file:
                if pattern.match(line):
                    logger.debug('Matching pattern %s for line %s for %s',pattern,line,path)
                    return True
    except FileNotFoundError:
        return True
    return False

def secret_files_iterator(use_git=False,path_pattern:Optional[str]=None):
    conf = get_sops_config()
    patterns = {}
    path_pattern_re = None
    if path_pattern is not None:
        path_pattern_re = re.compile(path_pattern)
    for rule in conf.get('creation_rules',[]):
        path_regex = rule.get('path_regex')
        logger.debug('Adding path_regex: %s',path_regex)
        if path_regex:
            patterns[re.compile(path_regex)] = rule
    if use_git:
        iterator = get_staged_files()
    else:
        iterator = iter_files()
    for path in iterator:
        logger.log(5,'Testing path: %s',path)
        rule = None
        if path_pattern_re is not None:
            if not path_pattern_re.match(path):
                continue
        for pattern in patterns:
            if pattern.match(path):
                rule = patterns[pattern]
        if rule is not None:
            yield path,rule
        else:
            logger.log(5,'no match for %s',path)

def manage_gitignore(dry_run=False,use_git=False,in_place=False,suffix='.enc'):
    files_to_ignore = []
    for path,rule in secret_files_iterator(use_git=use_git):
        if in_place or not path.endswith(suffix):
            files_to_ignore.append(path.lstrip('./'))
    files = '\n'.join(files_to_ignore)
    other_lines = get_gitignore_others()
    if not dry_run:
        write_gitignore(other_lines,files)
    else:
        print(files)

def get_gitignore_others():
    other_lines = []
    with open('.gitignore','r') as gitignore_file:
        record = True
        for line in gitignore_file:
            if line.startswith('#> managed by sops-wrapper'):
                record = False
            elif line.startswith('#< managed by sops-wrapper'):
                record = True
            elif record and line.strip():
                other_lines.append(line)
    return other_lines

def write_gitignore(other_lines,ours):
    with open('.gitignore','w') as gitignore_file:
        for line in other_lines:
            gitignore_file.write(line)
        gitignore_file.write('\n#> managed by sops-wrapper\n')
        for line in ours:
            gitignore_file.write(line)
        gitignore_file.write('\n#< managed by sops-wrapper')

def needs_encryption_adv(path,encrypted_path,cmd):
    with tempfile.TemporaryFile(mode='w+b') as outfile:
        try:
            subprocess.run(cmd+['--decrypt',encrypted_path],check=True,stdout=outfile,stderr=subprocess.PIPE)
        except:
            return False
        hasher = hashlib.sha256()
        outfile.seek(0)
        unenc = outfile.read()
        hasher.update(unenc)
    digest = hasher.hexdigest()
    hasher = hashlib.sha256()
    with open(path,'rb') as _file:
        hasher.update(_file.read())
    digest2 = hasher.hexdigest()
    return digest != digest2

def encrypt(
        dry_run=False,
        use_git=False,
        in_place=False,
        suffix='.enc',
        force:bool=False,
        sops_args:str='',
        path_pattern:Optional[str]=None,
    ):
    _cmd = ['sops']
    if sops_args:
        _cmd += shlex.split(sops_args)
    errors = []
    logger.debug('Making secret_files_iterator with: %s',path_pattern)
    for path,rule in secret_files_iterator(use_git=use_git,path_pattern=path_pattern):
        logger.debug('Checking path: %s',path)
        cmd = _cmd.copy()
        if 'input_type' in rule:
            cmd.append('--input-type')
            cmd.append(rule['input_type'])
        if 'output_type' in rule:
            cmd.append('--output-type')
            cmd.append(rule['output_type'])
        if not in_place:
            encrypted_path = f'{path}{suffix}'
        else:
            encrypted_path = path
        encrypted_regex = rule.get('encrypted_regex',None)
        if not force and in_place and is_encrypted(encrypted_path):
            logger.info(' %s already encrypted with sops',encrypted_path)
        elif encrypted_regex is not None and not needs_encryption(encrypted_regex,path):
            logger.log(5,'%s not matching any encrypted_regex',path)
        elif not in_place and path.endswith(suffix):
            logger.log(5,'Skipping path %s because endswith encrypt suffix',path)
        elif not force and needs_encryption_adv(path,encrypted_path,cmd):
            logger.info(' %s already latest version encrypted with sops',encrypted_path)
        else:
            try:
                if not in_place:
                    if dry_run:
                        print(f'would encrypt: {path} to {encrypted_path}')
                    else:
                        with open(encrypted_path,'wb') as outfile:
                            subprocess.run(cmd+['--encrypt',path],check=True,stdout=outfile)
                else:
                    if dry_run:
                        print(f'would encrypt: {path}')
                    else:
                        subprocess.run(cmd+['--in-place','--encrypt',path],check=True)
            except Exception as err:
                errors.append((path,err))
    if errors:
        raise Exception('found %s'%errors)

def decrypt(dry_run=False,use_git=False,in_place=False,suffix='.enc',force:bool=False,sops_args:str='',path_pattern:Optional[str]=None):
    _cmd = ['sops']
    if sops_args:
        _cmd += shlex.split(sops_args)
    for path,rule in secret_files_iterator(use_git=use_git,path_pattern=path_pattern):
        logger.debug('Checking path: %s',path)
        cmd = _cmd.copy()
        if not in_place and path.endswith(suffix):
            decrypted_path = path[:-len(suffix)]
        elif in_place:
            decrypted_path = path
        else:
            continue
        if not in_place or is_encrypted(path):
            if 'output_type' in rule:
                cmd.append('--output-type')
                cmd.append(rule['output_type'])
            if 'input_type' in rule:
                cmd.append('--input-type')
                cmd.append(rule['input_type'])
            if not in_place:
                if dry_run:
                    logger.info('would decrypted %s to %s',path,decrypted_path)
                else:
                    with open(decrypted_path,'wb') as outfile:
                        subprocess.run(cmd + ['--decrypt',path],check=True,stdout=outfile)
            else:
                if dry_run:
                    logger.info('would decrypted %s to %s',path,path)
                else:
                    subprocess.run(cmd+['--in-place','--decrypt',path],check=True)
        else:
            if in_place or path != path.rstrip(suffix):
                logger.info('%s already decrypted',path)


def main():
    parser = make_parser()
    kwargs = vars(parser.parse_args())
    log_level = kwargs.pop('log_level','info')
    try:
        log_level = int(log_level)
    except:
        log_level = log_level.upper()
    logging.basicConfig(level=log_level)
    if 'command' not in kwargs:
        parser.print_help()
    else:
        command = kwargs.pop('command')
        command(**kwargs)

if __name__ == '__main__':
    main()
