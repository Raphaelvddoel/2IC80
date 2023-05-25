"""This package contains everything related to DNS spoofing"""

import click

def spoof_dns():
    click.echo("spoofing target using all stored domains")


def spoof_dns_single():
    domain = click.prompt('Which domain do you want to spoof?')
    ip = click.prompt('Which IP should it route to?')