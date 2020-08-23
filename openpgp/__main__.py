#!/usr/bin/env python3
"""Main entry point for my OpenPGP implementation"""
import argparse
import logging
import os

from openpgp import common, signature
from openpgp import parse
from openpgp import display
from openpgp import create


LOAD_PATH_ENV = 'FA_MATHE_OPENPGP_LOADPATH'


def binary_file_data(file_name):
    """argparse.FileType won't work with binary stdin"""
    if file_name == '-':
        return sys.stdin.buffer.read()
    else:
        with open(file_name, 'rb') as f:
            return f.read()


def do_save_message(context: common.Context, argv: argparse.Namespace):
    """Write the selected message to STDOUT"""
    try:
        message = context.messages[argv.message]
    except IndexError:
        print('No message with index', argv.message, file=sys.stderr)
        return 2
    stdout_b = open(sys.stdout.fileno(), 'wb')
    stdout_b.write(message.data)


def do_pgpify(context: common.Context, argv: argparse.Namespace):  # noqa
    """Convert a message to PGP format"""
    try:
        data = binary_file_data(argv.file)
    except FileNotFoundError:
        print('No such file:', argv.file, file=sys.stderr)
        return 2
    msg = common.Message(
        data=data,
        data_type=argv.data_type,
        filename=(argv.filename or argv.file).encode()[-255:],
    )
    open(sys.stdout.fileno(), 'wb').write(create.write_message(msg))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--load',
        action='append',
        type=binary_file_data,
        help='Load the specified file. May be given multiple times and supplements'
             f' the {LOAD_PATH_ENV} environment variable.',
        default=[],
    )
    parser.add_argument(
        '--loglevel',
        choices='DEBUG INFO WARNING ERROR'.split(),
        type=str.upper,
        help='Set the logging level',
    )
    actions = parser.add_subparsers(
        description='The action to perform',
    )
    info_parser = actions.add_parser('info')
    info_parser.set_defaults(func=lambda c, a: (print(display.display(c)), 0)[1])
    repr_parser = actions.add_parser('repr')
    repr_parser.set_defaults(func=lambda c, a: (print(repr(c)), 0)[1])
    save_msg_parser = actions.add_parser('save-message')
    save_msg_parser.set_defaults(func=do_save_message)
    save_msg_parser.add_argument(
        '--message',
        help='The message index. Default: last message',
        type=int,
        default=-1,
    )
    pgpify_parser = actions.add_parser('pgpify')
    pgpify_parser.set_defaults(func=do_pgpify)
    pgpify_parser.add_argument(
        # We need the file name, so no type=binary_file_data
        'file',
        help='The file to convert to PGP format. Default: standard input.',
        nargs='?',
        default='-',
    )
    pgpify_parser.add_argument(
        '--filename',
        help='alternative filename to save',
    )
    pgpify_parser.add_argument(
        '--textmode',
        action='store_const',
        dest='data_type',
        const=common.DataType.TEXT,
        default=common.DataType.BINARY,
    )
    return parser.parse_args()


def main(args):
    context = common.Context()

    env_data = []
    for file in os.environ.get(LOAD_PATH_ENV, '').split(':'):
        try:
            with open(file, 'rb') as f:
                env_data.append(f.read())
        except OSError:
            logging.warning(f'error reading {file} (from {LOAD_PATH_ENV})')

    for data in env_data + args.load:
        context = parse.parse(context, data)
        context.temp = common.TempData()
    signature.verify_signatures(context)

    return (args.func or (lambda c, a: 0))(context, args)


if __name__ == '__main__':
    import sys
    args = parse_args()
    logging.basicConfig(  # noqa
        level=args.loglevel,
        stream=sys.stderr,
        format='{asctime} - {levelname}({name}): {message}',
        style='{',
    )
    sys.exit(main(args))
