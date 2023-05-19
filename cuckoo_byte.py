import click
from functions import poison

@click.group()
def cli():
    pass

@cli.command()
def arp():
    click.echo("This arp poisons")

@cli.command()
@click.option("-v", "--victim", type=str, help="The intended victim", default="10.0.0.1")
def arp_v(victim): # _ translate to - so the command will be arp-v
    click.echo(poison(victim))