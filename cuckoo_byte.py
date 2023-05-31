import click
from functions import *
from functions.general import list_interfaces, get_target_mac
from functions.arp import poison, restore_arp, mitm_arp


@click.group()
def cli():
    pass


# ------------------------------------------------- ARP ------------------------------------------------ #
@cli.command()
@click.option('-v', '--victim', type=str, help='The intended victim')
@click.option('-s', '--spoof', type=str, help='What ip do you want to impersonate')
def arp(victim, spoof):
    '''ARP poison a specified victim once'''
    click.echo('ARP Poisoning...')
    poison(victim, spoof)

@cli.command()
@click.option('-v', '--victim', type=str, help='The victim IP for ARP restoration')
@click.option('-s', '--spoof', type=str, help='The spoofed IP for ARP restoration')
def restore(victim, spoof):
    '''Restore the ARP table of the specified victim'''
    click.echo('Restoring ARP...')
    restore_arp(victim, spoof)

@cli.command()
@click.option('-v1', '--victim1', type=str, help='IP of victim 1')
@click.option('-v2', '--victim2', type=str, help='IP of victim 2')
def mitm(victim1, victim2):
    '''Execute a man in the middle attack using arp poisoning'''
    click.echo('Man-in-the-Middle attack in progress...')
    mitm_arp(victim1, victim2)

# ------------------------------------------------ General ----------------------------------------------- #
@cli.command()
def ls_if(): # _ translate to - so the command will be ls-if
    '''List the interfaces of your machine'''
    click.echo(list_interfaces())

@cli.command()
@click.option('-i', '--ip', type=str, help='The IP of the target you want the mac address of')
def target_mac(ip): # _ translate to - so the command will be target-mac
    '''Get the mac adress of a specified IP adress'''
    click.echo(f'Target MAC address: {get_target_mac(ip)}')


# ---- testing ----
# @cli.command()
# @click.option('-n', '--name', type=str, help='your first name', default='john')
# @click.option('-l', '--last-name', type=str, help='your last name', default='doe')
# def test(name, last_name):
#     click.echo(f'hello {name} {last_name}')