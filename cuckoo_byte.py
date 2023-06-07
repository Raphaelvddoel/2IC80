import click
from functions import *

@click.group()
def cli():
    pass

@cli.command()
def arp():
    click.echo('This arp poisons')

@cli.command()
@click.option('-s', '--source', type=str, help='The intended victim')
@click.option('-v', '--victim', type=str, help='The intended victim')
def arp_v(victim): # _ translate to - so the command will be arp-v
    click.echo(poison(victim))

@cli.command()
def ls_if(): # _ translate to - so the command will be ls-if
    click.echo(list_interfaces())

@cli.command()
@click.option('-i', '--ip', type=str, help='The IP of the target you want the mac address of')
def target_mac(ip): # _ translate to - so the command will be target-mac
    click.echo(get_target_mac(ip))

@cli.command()
def sniff():
    sniffer()

# ---- testing ----
@cli.command()
@click.option('-n', '--name', type=str, help='your first name', default='john')
@click.option('-l', '--last-name', type=str, help='your last name', default='doe')
def test(name, last_name):
    click.echo(f'hello {name} {last_name}')


@cli.command()
def testing_snif(ip): # _ translate to - so the command will be target-mac
    sniffer.main()