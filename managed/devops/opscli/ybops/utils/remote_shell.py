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
import time
import subprocess
import os
import pipes

from ybops.common.exceptions import YBOpsRuntimeError
from fabric import Connection
from paramiko.ssh_exception import NoValidConnectionsError

CONNECTION_ATTEMPTS = 5
CONNECTION_ATTEMPT_DELAY_SEC = 3


def retry_network_errors(command):
    attempt = 0
    while True:
        try:
            result = command()
            return result
        except NoValidConnectionsError as e:
            attempt += 1
            logging.warning("Connection attempt {} failed: {}".format(attempt, e.errors))
            if attempt >= CONNECTION_ATTEMPTS:
                raise e
            time.sleep(CONNECTION_ATTEMPT_DELAY_SEC)


class RemoteShell(object):
    """RemoteShell class is used run remote shell commands against nodes using fabric.
    """

    def __init__(self, options):
        assert options["ssh_user"] is not None, 'ssh_user is required option'
        assert options["ssh_host"] is not None, 'ssh_host is required option'
        assert options["ssh_port"] is not None, 'ssh_port is required option'
        assert options["private_key_file"] is not None, 'private_key_file is required option'

        # self.ssh_conn = Connection(
        #     host=options.get("ssh_host"),
        #     user=options.get("ssh_user"),
        #     port=options.get("ssh_port"),
        #     connect_kwargs={'key_filename': [options.get("private_key_file")]}
        # )
        self.host = options.get("ssh_host")
        self.user = options.get("ssh_user")
        self.port = options.get("ssh_port")
        self.key_file = options.get("private_key_file")

    def run_command_raw(self, command):
        logging.info("[app] Trying Manual REMOTE COMMAND EXECUTION with command, {}, {}".format(command, self.user))
        out = run_command(['ssh',
                '-o', 'StrictHostKeyChecking=no',
                # '-o', 'UserKnownHostsFile=/dev/null',
                # Control flags here are for ssh multiplexing (reuse the same ssh connections).
                # '-o', 'ControlPersist=1m',
                '-K', self.key_file,
                '-p', self.port,
                '%s@%s' % (self.user, self.host),
                command])
        logging.info("[app] can ssh output {}".format(out))
        return out
        # result = inOutErr[1].readlines()

    def run_command(self, command):
        result = self.run_command_raw(command)

        # if result.exited:
        #     raise YBOpsRuntimeError(
        #         "Remote shell command '{}' failed with "
        #         "return code '{}' and error '{}'".format(command.encode('utf-8'),
        #                                                  result.stderr.encode('utf-8'),
        #                                                  result.exited)
        #     )

        return result

    def put_file(self, local_path, remote_path):
        out = run_command(['scp',
            '-o', 'StrictHostKeyChecking=no',
            '-K', self.key_file,
            '-P', self.port,
            local_path,
            '%s@%s:%s' % (self.user, self.host, remote_path)])
        logging.info("[app] put file output {}".format(out))

    # Checks if the file exists on the remote, and if not, it puts it there.
    def put_file_if_not_exists(self, local_path, remote_path, file_name):
        result = self.run_command('ls ' + remote_path)
        if file_name not in result.stdout:
            self.put_file(local_path, os.path.join(remote_path, file_name))


def run_command(args, num_retry=1, timeout=10, env=None, **kwargs):
    cmd_as_str = quote_cmd_line_for_bash(args)
    logging.info("[app], command as string, {}".format(cmd_as_str))
    while num_retry > 0:
        num_retry = num_retry - 1

        try:
            proc_env = os.environ.copy()
            proc_env.update(env if env is not None else {})

            subprocess_result = str(subprocess.check_output(
                args, stderr=subprocess.STDOUT,
                env=proc_env, **kwargs).decode('utf-8', errors='replace'))
            logging.info("[app] Here is the command output, {}".format(subprocess_result))
            return subprocess_result
        except subprocess.CalledProcessError as e:
            logging.error("Failed to run command [[ {} ]]: code={} output={}".format(
                cmd_as_str, e.returncode, str(e.output.decode('utf-8', errors='replace')
                                                        .encode("ascii", "ignore")
                                                        .decode("ascii"))))
            sleep_or_raise(num_retry, timeout, e)
        except Exception as ex:
            logging.error("Failed to run command [[ {} ]]: {}".format(cmd_as_str, ex))
            sleep_or_raise(num_retry, timeout, ex)

def sleep_or_raise(num_retry, timeout, ex):
    if num_retry > 0:
        logging.info("Sleep {}... ({} retries left)".format(timeout, num_retry))
        time.sleep(timeout)
    else:
        raise ex

def quote_cmd_line_for_bash(cmd_line):
    if not isinstance(cmd_line, list) and not isinstance(cmd_line, tuple):
        raise Exception("Expected a list/tuple, got: [[ {} ]]".format(cmd_line))
    return ' '.join([pipes.quote(str(arg)) for arg in cmd_line])
