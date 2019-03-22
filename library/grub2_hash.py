#!/usr/bin/env python
#
# Copyright 2015 David Sastre Medina <d.sastre.medina@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#    General Public License <gnu.org/licenses/gpl.html> for more details.

from hashlib import pbkdf2_hmac
from os import urandom
from binascii import hexlify
from ansible.module_utils.basic import *


DOCUMENTATION = '''
---
module: grub2_hash
short_description: Generate a PBKDF2 password/passphrase hash
description:
    - Generates a PBKDF2 (RFC2898) hash string suitable for
      use in a GRUB2 configuration file.
      Based on an original idea from
      U(https://github.com/ryran/burg2-mkpasswd-pbkdf2.git)
version_added: '2.6'
author: 'David Sastre Medina <d.sastre.medina@gmail.com> @dawud'
notes:
    - This module is useful for GNU/Linux systems that use GRUB2
requirements:
    - GNU/Linux
    - GRUB2
options:
    iteration_count:
        description:
            - Number of iterations of the underlying pseudo-random function.
        required: false
        default: 100000
        version_added: 0.1
    salt:
        description:
            - Lenght of the salt (even number)
        required: false
        default: 64
        version_added: 0.1
    passphrase:
        description:
            - Passphrase to hash
        required: true
        version_added: 0.1
'''

EXAMPLES = '''
# Using defaults
- grub2_hash:
    passphrase: "{{ vault_user_grub2_password }}"
  register: hash

- debug:
    msg: "{{ hash.line }}"

# Using explicit values
- grub2_hash:
    iteration: 200000
    salt: 256
    passphrase: "{{ vault_user_grub2_password }}"
  register: hash

- debug:
  msg: "{{ hash.line }}"
'''

RETURN = '''
line:
    description: line containing hased password
    returned: success
    type: string
    sample: "grub.pbkdf2.sha512.100000.AC977AB17BE0B8D0CC1BA74C0223BE73D10DB94FE7EBAA4078EEFB45ADCF67F52636DE64D6A32FB213C95E8862862EC14E4627EFE81CE2A88DE55CCC71D42A99.743A87E29DAA00057D7B15DA730FC06C6691237D656EE9BC422546B403FC204E66ED38107AE021BC58AACE4DE28CC09D04728C414D949FF887960FEC34DF5F56"
'''

def grub2_mkpasswd_pbkdf2(passphrase, iterCount=100000, saltLength=64, dryRun=False):

    result = dict(passphrase=passphrase, iterCount=iterCount, saltLength=saltLength)

    if dryRun:
        result['failed'] = False
        result['changed'] = False
        result['line'] = 'null'
        result['msg'] = 'OK'

        return result
    else:
        try:
            algo = 'sha512'
            binSalt = urandom(saltLength)
            hexSalt = hexlify(binSalt).upper()
            passHash = hexlify(pbkdf2_hmac(algo, passphrase, binSalt, iterCount)).upper()

            result['failed'] = False
            result['changed'] = True
            result['line'] = "grub.pbkdf2.{}.{}.{}.{}".format(algo, iterCount, hexSalt, passHash)
            result['msg'] = 'OK'

            return result

        except Exception as e:
            result['failed'] = True
            result['changed'] = False
            result['msg'] = e.msg

            return result

            raise e

def main():
    module = AnsibleModule(
        argument_spec=dict(
            iteration_count=dict(required=False, type='int', default=100000),
            salt=dict(required=False, type='int', default=64),
            passphrase=dict(required=True, default=None, type='str'),
        ),
        supports_check_mode=True
    )

    iteration_count = module.params['iteration_count']
    salt = module.params['salt']
    if not salt % 2 == 0:
        module.fail_json(msg='Salt length must be an even number.')
    passphrase = module.params['passphrase']

    result = grub2_mkpasswd_pbkdf2(passphrase, iteration_count, salt, module.check_mode)

    if result['failed']:
        module.fail_json(
            iteration_count=iteration_count,
            salt=salt,
            passphrase=passphrase,
            changed=result['changed'],
            msg=result['msg'],
            result=result
        )

    module.exit_json(
        line = result['line'],
        changed=result['changed'],
        msg=result['msg'],
    )


if __name__ == '__main__':
    main()
