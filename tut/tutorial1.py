from ad import Client, Creds, activate

domain = 'freeadi.org'
user = 'Administrator'
password = 'Pass123'

creds = Creds(domain)
creds.acquire(user, password)
activate(creds)

client = Client(domain)
users = client.search('(objectClass=user)')
for dn,attrs in users:
    name = attrs['sAMAccountName'][0]
    print '-> %s' % name
