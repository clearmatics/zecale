# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


from click import command, argument, Context, pass_context, ClickException


@command()
@argument("verification_key_file")
@pass_context
def nested_verification_key_hash(
        ctx: Context,
        verification_key_file: str) -> None:
    raise ClickException("not implemented yet")
