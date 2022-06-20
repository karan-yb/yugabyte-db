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


# def __formatsshV2Keys(key, public_key):
#     """Format private key file, & return the formatted SSH2 key.
#     :param key: private key file.
#     :param public_key: if Public key is required.
#     :return: Formatted key.
#     """

#     # Check if the sshg3 client binaries are present on the platform
#     try:
#         run_command(['command -v /usr/bin/ssh-keygen-g3 /dev/null'])
#     except subprocess.CalledProcessError as e:
#         logging.info("[app], sshg3 client is not installed on the system")
#         raise YBOpsRuntimeError("SSHG3 client is not installed on the system.") 

#     if public_key:
#         run_command([
#             'ssh-keygen-g3',
#             '-D', key
#         ])
#         # file will be saved with .pub extension
#         p_key_file = key + '.pub'
#         p_key = None
#         with open(p_key_file) as f:
#             p_key = f.read()

#         return p_key
    
#     with open(key) as f:
#         return f.read()


# def __formatsshKeys(key, public_key):
#     """Format private key file, & return the formatted SSH key.
#     :param key: private key file.
#     :param public_key: if Public key is required.
#     :return: Formatted key.
#     """
#     if public_key:
#         return key.publickey().exportKey("OpenSSH").decode('utf-8')
    
#     return key.exportKey("PEM").decode('utf-8')


# def format_ssh_key(key, public_key):
#     """Format private key file, & return the formatted key.
#     :param key: private key file.
#     :param public_key: if Public key is required.
#     :return: Formatted key.
#     """
#     key_formatter = {
#         SSHV2: __formatsshV2Keys,
#         SSH: __formatsshKeys
#     }

#     key_type = parse_private_key(key)
#     return key_formatter.get(key_type)(key, public_key)


# def validated_key_file(key_file):
#     """This method would validate a given key file and raise a exception if the file format
#     is incorrect or not found.
#     Args:
#         key_file (str): Key file name
#         public_key (bool): Denote if the key file is public key or not.
#     Returns:
#         key (RSA Key): RSA key data
#     """

#     if not os.path.exists(key_file):
#         raise YBOpsRuntimeError("Key file {} not found.".format(key_file))

#     # return key_file
#     with open(key_file) as f:
#         return RSA.importKey(f.read())


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

    ssh_key_flag = '-K'
    if key_type == SSH:
        ssh_key_flag = '-i'
    cmd = []

    if not src_filepath and not dest_filepath:
        cmd = ['ssh', '-p', str(port)]
    else:
        cmd = ['scp', '-P', str(port)]

    if len(extra_commands) != 0:
        cmd.extend(extra_commands)

    cmd.extend([
        '-o', 'StrictHostKeyChecking=no',
        ssh_key_flag, ssh_key_file,
    ])

    if not src_filepath and not dest_filepath:
        cmd.extend([
            '%s@%s' % (username, host_name),
            command
        ])
    else:
        cmd.extend([
            src_filepath,
            '%s@%s:%s' % (username, host_name, dest_filepath)
        ])
    return cmd


def get_ssh_client(policy=paramiko.AutoAddPolicy):
    """This method returns a paramiko SSH client with the appropriate policy
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(policy())
    return ssh_client


def _remote_exec_command(host, username, pkey, port, ssh_type, cmd):
    cmd = __generate_shell_command(
        host, port, username, pkey, 
        key_type=ssh_type,
        command=cmd
    )
    logging.info("[app], Executing cmd {} on the remote server".format(cmd))
    return _run_command(cmd)

def _run_command(args, num_retry=1, timeout=10, **kwargs):
    cmd_as_str = quote_cmd_line_for_bash(args)
    process = subprocess.Popen(args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

    while num_retry > 0:
        num_retry = num_retry - 1

        try:
            process = subprocess.Popen(args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            output, err = process.communicate()
            if process.returncode != 0:
                logging.error("Failed to run command [[ {} ]]: code={} output={}".format(
                    cmd_as_str, process.returncode, err))
                sleep_or_raise(num_retry, timeout, Exception(err))
            return output, err
        
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


# def __get_paramiko_ssh_client(host_name, port, username, ssh_key_file, key_type):
#     ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_file)
#     ssh_client = __get_ssh_client()
#     try:
#         ssh_client.connect(hostname=host_name,
#                         username=username,
#                         pkey=ssh_key,
#                         port=port,
#                         timeout=SSH_TIMEOUT,
#                         banner_timeout=SSH_TIMEOUT)
#     except (paramiko.ssh_exception.NoValidConnectionsError,
#             paramiko.ssh_exception.AuthenticationException,
#             paramiko.ssh_exception.SSHException,
#             socket.timeout,
#             socket.error,
#             EOFError) as e:
#         raise e

#     return ssh_client


# def __shellcanSSH(host_name, port, username, ssh_key_file, key_type):
    # cmd = __generate_shell_command(
    #     host_name, port, username, ssh_key_file,
    #     command='source /etc/os-release && echo "$NAME $VERSION_ID"',
    #     key_type=key_type
    # )
#     inOutErr = run_command(cmd)
#     result = inOutErr[1].readlines()
#     if len(result) == 0 or result[0].strip().lower() != "centos linux 7":
#         return False
    
#     return True


# def __paramikocanSSH(host_name, port, username, ssh_key_file, key_type):
#     ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_file)
#     ssh_client = __get_paramiko_ssh_client()
#     if ssh_client is not None:
#         try:
#             ssh_client.invoke_shell()
#             return True
#         except Exception as e:
#             return False
#         finally:
#             ssh_client.close()
#     return False


# def can_ssh(host_name, port, username, ssh_key_file):
#     """This method tries to ssh to the host with the username provided on the port.
#     and returns if ssh was successful or not.
#     Args:
#         host_name (str): SSH host IP address
#         port (int): SSH port
#         username (str): SSH username
#         ssh_key_file (str): SSH key file
#     Returns:
#         (boolean): If SSH was successful or not.
#     """
#     ssh_switcher = {
#         SSHV2: __shellcanSSH,
#         SSH: __paramikocanSSH
#     }

#     key_type = parse_private_key(ssh_key_file)
#     return ssh_switcher.get(key_type)(host_name, port, username, ssh_key_file, key_type)


# def get_ssh_host_port(host_info, custom_port, default_port=False):
#     """This method would return ssh_host and port which we should use for ansible. If host_info
#     includes a ssh_port key, then we return its value. Otherwise, if the default_port param is
#     True, then we return a Default SSH port (22) else, we return a custom ssh port.
#     Args:
#         host_info (dict): host_info dictionary that we fetched from inventory script, we
#                           fetch the private_ip from that.
#         default_port(boolean): Boolean to denote if we want to use default ssh port or not.
#     Returns:
#         (dict): a dictionary with ssh_port and ssh_host data.
#     """
#     ssh_port = host_info.get("ssh_port")
#     if ssh_port is None:
#         ssh_port = (DEFAULT_SSH_PORT if default_port else custom_port)
#     return {
#         "ssh_port": ssh_port,
#         "ssh_host": host_info["private_ip"]
#     }


# def wait_for_ssh(host_ip, ssh_port, ssh_user, ssh_key, num_retries=SSH_RETRY_LIMIT):
#     """This method would basically wait for the given host's ssh to come up, by looping
#     and checking if the ssh is active. And timesout if retries reaches num_retries.
#     Args:
#         host_ip (str): IP Address for which we want to ssh
#         ssh_port (str): ssh port
#         ssh_user (str): ssh user name
#         ssh_key (str): ssh key filename
#     Returns:
#         (boolean): Returns true if the ssh was successful.
#     """
#     retry_count = 0
#     while retry_count < num_retries:
#         if can_ssh(host_ip, ssh_port, ssh_user, ssh_key):
#             return True

#         time.sleep(1)
#         retry_count += 1

#     return False


# def generate_rsa_keypair(key_name, destination='/tmp'):
#     """This method would generate a RSA Keypair with an exponent of 65537 in PEM format,
#     We will also make the files once generated READONLY by owner, this is need for SSH
#     to work.
#     Args:
#         key_name(str): Keypair name
#         destination (str): Destination folder
#     Returns:
#         keys (tuple): Private and Public key files.
#     """
#     new_key = RSA.generate(RSA_KEY_LENGTH)
#     if not os.path.exists(destination):
#         raise YBOpsRuntimeError("Destination folder {} not accessible".format(destination))

#     public_key_filename = os.path.join(destination, "{}.pub".format(key_name))
#     private_key_filename = os.path.join(destination, "{}.pem".format(key_name))
#     if os.path.exists(public_key_filename):
#         raise YBOpsRuntimeError("Public key file {} already exists".format(public_key_filename))
#     if os.path.exists(private_key_filename):
#         raise YBOpsRuntimeError("Private key file {} already exists".format(private_key_filename))

#     with open(public_key_filename, "w") as f:
#         f.write(format_ssh_key(new_key, public_key=True))
#         os.chmod(f.name, stat.S_IRUSR)
#     with open(private_key_filename, "w") as f:
#         f.write(format_ssh_key(new_key, public_key=False))
#         os.chmod(f.name, stat.S_IRUSR)

#     return private_key_filename, public_key_filename


# def scp_to_tmp(filepath, host, user, port, private_key):
#     dest_path = os.path.join("/tmp", os.path.basename(filepath))
#     logging.info("[app] Copying local '{}' to remote '{}'".format(
#         filepath, dest_path))
    
#     extra_commands = [
#         "-o", "ServerAliveInterval=30",
#         "-o", "ServerAliveCountMax=20",
#         "-o", "ControlMaster=auto",
#         "-o", "ControlPersist=600s",
#         "-o", "IPQoS=throughput",
#         "-vvvv"
#     ]
#     key_type = parse_private_key(private_key)

#     scp_cmd = __generate_shell_command(
#         host, port, user, private_key, 
#         extra_commands=extra_commands,
#         src_filepath=filepath,
#         dest_filepath=dest_path,
#         key_type=key_type
#     )
#     # Save the debug output to temp files.
#     out_fd, out_name = tempfile.mkstemp(text=True)
#     err_fd, err_name = tempfile.mkstemp(text=True)
#     # Start the scp and redirect out and err.
#     proc = subprocess.Popen(scp_cmd, stdout=out_fd, stderr=err_fd)
#     # Wait for finish and cleanup FDs.
#     proc.wait()
#     os.close(out_fd)
#     os.close(err_fd)
#     # In case of errors, copy over the tmp output.
#     if proc.returncode != 0:
#         timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
#         shutil.copyfile(out_name, "/tmp/{}-{}.out".format(host, timestamp))
#         shutil.copyfile(err_name, "/tmp/{}-{}.err".format(host, timestamp))
#     # Cleanup the temp files now that they are clearly not needed.
#     os.remove(out_name)
#     os.remove(err_name)
#     return proc.returncode


# def __execute_cmd_paramiko(host_name, port, username, ssh_key_file, cmd, key_type):
#     ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_file)
#     ssh_client = __get_paramiko_ssh_client()
#     if ssh_client is not None:
#         try:
#             stdin, stdout, stderr = ssh_client.exec_command(cmd)
#         except Exception as e:
#             return False
#         finally:
#             ssh_client.close()
#     return YBOpsRuntimeError("Authentication to the remote host failed.")


# def __execute_shell_cmd(host_name, port, username, ssh_key_file, cmd, key_type):
#     stderr


# def execute_cmd(host_name, port, username, ssh_key_file, cmd):
#     """This method tries to execute the command on the given host.
#     Args:
#         host_name (str): SSH host IP address
#         port (int): SSH port
#         username (str): SSH username
#         ssh_key_file (str): SSH key file
#     Returns:
#         (boolean): Command output
#     """
#     ssh_cmd_switcher = {
#         SSHV2: __execute_shell_cmd,
#         SSH: __execute_cmd_paramiko
#     }

#     key_type = parse_private_key(ssh_key_file)
#     return ssh_cmd_switcher.get(key_type)(host_name, port, username, ssh_key_file, cmd, key_type)