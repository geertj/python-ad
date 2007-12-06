from ad import Client, Creds, Locator, activate

domain = 'freeadi.org'
user = 'Administrator'
password = 'Pass123'

creds = Creds(domain)
creds.acquire(user, password)
activate(creds)

locator = Locator()
pdc = locator.locate(domain, role='pdc')

client = Client(domain)
users = client.search('(objectClass=user)', server=pdc)
for dn,attrs in users:
    name = attrs['sAMAccountName'][0]
    print '-> %s' % name
