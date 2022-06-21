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
from ybops.utils.ssh import check_ssh2_bin_present, _remote_exec_command, SSH, SSHV2

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

        self.use_ssh2_connection = check_ssh2_bin_present()
        if self.use_ssh2_connection:
            self.host = options.get("ssh_host")
            self.user = options.get("ssh_user")
            self.port = options.get("ssh_port")
            self.key_file = options.get("private_key_file")
        else:
            self.ssh_conn = Connection(
                host=options.get("ssh_host"),
                user=options.get("ssh_user"),
                port=options.get("ssh_port"),
                connect_kwargs={'key_filename': [options.get("private_key_file")]}
            )

    def run_command_raw(self, command):
        if self.use_ssh2_connection:
            try:
                key_type = SSHV2 if self.use_ssh2_connection else SSH
                output = _remote_exec_command(
                    self.host, self.user, self.key_file, self.port,
                    key_type,
                    command=command
                )
                logging.info("Executing remote command, {}".format(command))
                return output
            except Exception as e:
                raise YBOpsRuntimeError(
                    "Remote shell command '{}' failed with "
                    "error '{}'".format(command.encode('utf-8'), e)
                )
        else:
            return retry_network_errors(lambda: self.ssh_conn.run(command, hide=True, warn=True))

    def run_command(self, command):
        result = self.run_command_raw(command)

        if not self.use_ssh2_connection and result.exited:
            raise YBOpsRuntimeError(
                "Remote shell command '{}' failed with "
                "return code '{}' and error '{}'".format(command.encode('utf-8'),
                                                         result.stderr.encode('utf-8'),
                                                         result.exited)
            )

        return result

    def put_file(self, local_path, remote_path):
        if self.use_ssh2_connection:
            try:
                key_type = SSHV2 if self.use_ssh2_connection else SSH
                output = _remote_exec_command(
                    self.host, self.user, self.key_file, self.port,
                    key_type,
                    src_filepath=local_path,
                    dest_filepath=remote_path
                )
                return output
            except Exception as e:
                raise YBOpsRuntimeError(
                    "Scp failed with error '{}'".format(e)
                )
        else:
            return retry_network_errors(lambda: self.ssh_conn.put(local_path, remote_path))

    # Checks if the file exists on the remote, and if not, it puts it there.
    def put_file_if_not_exists(self, local_path, remote_path, file_name):
        result = self.run_command('ls ' + remote_path)
        if not self.use_ssh2_connection:
            result = result.stdout
        if file_name not in result:
            self.put_file(local_path, os.path.join(remote_path, file_name))
