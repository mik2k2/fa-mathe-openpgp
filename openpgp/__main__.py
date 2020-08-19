#!/usr/bin/env python3
"""Main entry point for my OpenPGP implementation"""
import argparse
import logging
from openpgp import common
from openpgp import parse
from openpgp import display
from openpgp import create


def binary_file_data(file_name):
    """argparse.FileType won't work with binary stdin"""
    if file_name == '-':
        return sys.stdin.buffer.read()
    else:
        with open(file_name, 'rb') as f:
            return f.read()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--load',
        nargs='*',
        type=binary_file_data,
        help='Load the specified file. May be given multiple times',
        default=[],
    )
    parser.add_argument(
        '--loglevel',
        choices='DEBUG INFO WARNING ERROR'.split(),
        type=str.upper,
        help='Set the logging level',
    )
    # actions = parser.add_subparsers()
    # actions.add_parser('info')
    # actions.add_parser('repr')
    # actions.add_parser('save-message')
    # actions.add_parser('encrypt')
    parser.add_argument(
        'action',
        choices='info repr save-message encrypt'.split(),
        help='Perform this action',
    )
    return parser.parse_args()


def main(args):
    context = common.Context()
    for data in args.load:
        context = parse.parse(context, data)
        context.temp = common.TempData()
    if args.action == 'info':
        print(display.display(context))
    elif args.action == 'repr':
        print(repr(context))
    elif args.action == 'save-message':
        if not context.messages:
            print('No messages available', file=sys.stderr)
            sys.exit(2)
        else:
            stdout_b = open(sys.stdout.fileno(), 'wb')
            stdout_b.write(context.messages[-1].data)
    elif args.action == 'encrypt':
        stdout_b = open(sys.stdout.fileno(), 'wb')
        msg = common.Message(
            data=b'Hello!',
            data_type=common.DataType.TEXT,
            filename=b'',
        )
        stdout_b.write(create.encrypt_data(
            create.write_message(msg),
            context.keys.values(),
            common.SymmetricAlgorithm.AES256)
        )
    else:
        raise type('NeverHappens', (Exception,), {})


if __name__ == '__main__':
    import sys
    args = parse_args()
    logging.basicConfig(  # noqa
        level=args.loglevel,
        stream=sys.stderr,
        format='{asctime} - {levelname}({name}): {message}',
        style='{',
    )
    main(args)
