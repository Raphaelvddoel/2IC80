import json
import re
import click

FILENAME = 'storage/domains.json'

def add_dns_domain():
    '''
    Add domain to list of stored domains used when dns spoofing
    '''

    domain = click.prompt('Which domain do you want to spoof? Please enter the domain without www.')
    ip = click.prompt('Which IP should it route to?')

    domain = strip_domain(domain)

    if not validate_domain(domain):
        click.echo('invalid domain')
        return

    if not validate_ip(ip):
        click.echo('invalid ip')
        return

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

    if not validate_index(index):
        click.echo('Invalid input')
        return

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


def validate_index(index, data):
    if not index.isdigit():
        return False

    index = int(index)
    data_length = len(data)

    if 1 <= index <= data_length:
        return True
    
    return False


def strip_domain(domain):
    # Strip leading "www." if present
    if domain.startswith("www."):
        return domain[4:]

    return domain


def validate_domain(domain):
    # Regular expression pattern for domain validation
    pattern = r"^(?!:\/\/)(?:[a-zA-Z0-9-_]+\.){1,}[a-zA-Z]{2,}$"

    if re.match(pattern, domain):
        return True

    return False


def validate_ip(ip):
    # Regular expression pattern for IP validation
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

    if re.match(pattern, ip):
        return True

    return False
