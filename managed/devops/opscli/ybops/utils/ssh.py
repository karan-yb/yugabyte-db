#!/usr/bin/env python
#
# Copyright 2019 YugaByte, Inc. and Contributors
#
# Licensed under the Polyform Free Trial License 1.0.0 (the "License"); you
# may not use this file except in compliance with the License. You
# may obtain a copy of the License at
#
# https://github.com/YugaByte/yugabyte-db/blob/master/licenses/POLYFORM-FREE-TRIAL-LICENSE-1.0.0.txt

import logging
import os
import pipes
import paramiko
import socket
import subprocess
import time

from Crypto.PublicKey import RSA

from ybops.common.exceptions import YBOpsRuntimeError
from ybops.utils.ssh_process import SSHProcess

SSHV2 = 'ssh_v2'
SSH = 'ssh'


def parse_private_key(key):
    """Parses the private key file, & returns
    the underlying format that the key uses.
    :param key: private key file.
    :return: Private key type(One of SSHv2/SSH).
    """
    if key is None:
        raise YBOpsRuntimeError("Private key file not specified. Returning.")

    with open(key) as f:
        key_data = f.read()
        try:
            RSA.importKey(key_data)
            return SSH
        except ValueError:
            '''
            SSH2 encrypted keys contains Subject & comment in the generated body.
            '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----'
            'Subject: user'
            'Comment: "2048-bit rsa'
            '''
            key_val = key_data.split('\n')
            if 'Subject' in key_val[1] and 'Comment' in key_val[2]:
                return SSHV2

    logging.info("[app], specified key format is not supported.")
    raise YBOpsRuntimeError("Specified key format is not supported.")


def check_ssh2_bin_present():
    """Checks if the ssh2 is installed on the node
    :return: True/False
    """
    output = _run_command(['command', '-v', '/usr/bin/sshg3', '/dev/null'])
    return True if output is not None else False


def __generate_shell_command(host_name, port, username, ssh_key_file, **kwargs):
    '''
        This method generates & returns the actual shell command,
        that will be executed as subprocess.
    '''
    # The flag on which we specify the private_key_file differs in
    # ssh version. In SSH it is specified via `-i` will in SSH2 via `-K`
    key_type = kwargs.get('key_type', SSHV2)
    extra_commands = kwargs.get('extra_commands', [])
    command = kwargs.get('command', None)
    src_filepath = kwargs.get('src_filepath', None)
    dest_filepath = kwargs.get('dest_filepath', None)
    is_file_download = kwargs.get('get_from_remote', False)

    ssh2_bin_present = check_ssh2_bin_present()
    ssh_key_flag = '-K'
    if not ssh2_bin_present:
        ssh_key_flag = '-i'
    cmd = []

    if not src_filepath and not dest_filepath:
        cmd = ['ssh', '-p', str(port)]
    else:
        cmd = ['scp', '-P', str(port)]

    if len(extra_commands) != 0:
        cmd += extra_commands

    cmd.extend([
        '-o', 'StrictHostKeyChecking=no',
        ssh_key_flag, ssh_key_file,
    ])

    if not src_filepath and not dest_filepath:
        cmd.extend([
            '%s@%s' % (username, host_name)
        ])
        if isinstance(command, list):
            cmd += command
        else:
            cmd.append(command)
    else:
        if not is_file_download:
            cmd.extend([
                src_filepath,
                '%s@%s:%s' % (username, host_name, dest_filepath)
            ])
        else:
            cmd.extend([
                '%s@%s:%s' % (username, host_name, src_filepath),
                dest_filepath
            ])
    return cmd


def get_ssh_client(policy=paramiko.AutoAddPolicy):
    """This method returns a paramiko SSH client with the appropriate policy
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(policy())
    return ssh_client


def _remote_exec_command(host, username, pkey, port, ssh_type, **kwargs):
    cmd = __generate_shell_command(
        host, port, username, pkey,
        key_type=ssh_type,
        **kwargs
    )
    output = _run_command(cmd)
    return output


def _run_command(args, num_retry=1, timeout=1, **kwargs):
    cmd_as_str = quote_cmd_line_for_bash(args)
    logging.info("[app] Executing command \"{}\" on the remote server".format(cmd_as_str))
    while num_retry > 0:
        num_retry = num_retry - 1
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            output, err = process.communicate()
            if process.returncode != 0:
                raise YBOpsRuntimeError(err)
            return output.decode('utf-8')

        except YBOpsRuntimeError as e:
            logging.error("Failed to run command [[ {} ]]: code={} output={}".format(
                    cmd_as_str, process.returncode, err))
            raise e

        except Exception as ex:
            logging.error("Failed to run command [[ {} ]]: {}".format(cmd_as_str, ex))
            sleep_or_raise(num_retry, timeout, ex)


def quote_cmd_line_for_bash(cmd_line):
    if not isinstance(cmd_line, list) and not isinstance(cmd_line, tuple):
        raise Exception("Expected a list/tuple, got: [[ {} ]]".format(cmd_line))
    return ' '.join([pipes.quote(str(arg)) for arg in cmd_line])


def sleep_or_raise(num_retry, timeout, ex):
    if num_retry > 0:
        logging.info("Sleep {}... ({} retries left)".format(timeout, num_retry))
        time.sleep(timeout)
    else:
        raise ex
