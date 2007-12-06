from ad import Client, Creds, Locator, activate

domain = 'freeadi.org'
user = 'Administrator'
password = 'Pass123'

levels = \
{
    '0': 'windows 2000',
    '1': 'windows 2003 interim',
    '2': 'windows 2003'
}

creds = Creds(domain)
creds.acquire(user, password)
activate(creds)

locator = Locator()
server = locator.locate(domain)

client = Client(domain)
result = client.search(base='', scope='base', server=server)
assert len(result) == 1
dn, attrs = result[0]
level = attrs['forestFunctionality'][0]
level = levels.get(level, 'unknown')
print 'Forest functionality level: %s' % level
