import click
import json

FILENAME = 'storage/domains.json'

def add_dns_domain():
    '''
    Add domain to list of stored domains used when dns spoofing
    '''
    
    domain = click.prompt('Which domain do you want to spoof?')
    ip = click.prompt('Which IP should it route to?')

    data = get_domains()

    data[domain] = ip

    store_domains(data)


def remove_dns_domain():
    '''
    Remove domain from list of stored domains used when dns spoofing
    '''

    data = get_domains()

    for index, (key, value) in enumerate(data.items(), start=1):
        click.echo(f'{index}) {key}: {value}')

    index = click.prompt('Please enter the number of the domain/ip combination that you want te remove')

    # Convert index to key
    index = int(index)  # Convert the input to an integer
    keys = list(data.keys())  # Get the keys from the dictionary
    selected_key = keys[index - 1]  # Subtract 1 from the index to match the 0-based index of the list

    del data[selected_key]  # Delete the key-value pair

    # Save the updated data back to the file
    store_domains(data)


def show_dns_domains():
    '''
    Show all domains stored to use for dns spoofing
    '''
    data = get_domains()

    click.echo('The following combinations are stored')

    for index, (key, value) in enumerate(data.items(), start=1):
        click.echo(f'{index}) {key}: {value}')


def get_domains():
    with open(FILENAME, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return {}


def store_domains(data):
    with open(FILENAME, 'w') as file:
        json.dump(data, file, indent=4, separators=(',', ': '))