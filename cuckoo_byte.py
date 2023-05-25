import click
from functions import *
from functions.general import list_interfaces, get_target_mac
from functions.arp import poison, restore_arp, mitm


@click.group()
def cli():
    pass

@cli.command()
def arp(source, victim):
    click.echo('This ARP poisons')

@cli.command()
@click.option('-s', '--source', type=str, help='The intended victim')
@click.option('-v', '--victim', type=str, help='The intended victim')
def arp_v(victim):
    click.echo(poison(victim))

@cli.command()
@click.option('-d', '--destination', type=str, help='The destination IP for ARP restoration')
@click.option('-s', '--source', type=str, help='The source IP for ARP restoration')
def restore(destination, source):
    click.echo('Restoring ARP...')
    restore_arp(destination, source)

@cli.command()
@click.option('-t1', '--target1', type=str, help='IP of target 1')
@click.option('-t2', '--target2', type=str, help='IP of target 2')
def mitm(target1, target2):
    click.echo('Man-in-the-Middle attack in progress...')
    mitm(target1, target2)    

@cli.command()
def ls_if(): # _ translate to - so the command will be ls-if
    click.echo(list_interfaces())

@cli.command()
@click.option('-i', '--ip', type=str, help='The IP of the target you want the mac address of')
def target_mac(ip): # _ translate to - so the command will be target-mac
    click.echo(f'Target MAC address: {get_target_mac(ip)}')

# ---- testing ----
@cli.command()
@click.option('-n', '--name', type=str, help='your first name', default='john')
@click.option('-l', '--last-name', type=str, help='your last name', default='doe')
def test(name, last_name):
    click.echo(f'hello {name} {last_name}')