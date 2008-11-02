#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from ad.protocol import asn1
from ad.protocol import ldapfilter


SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

DEREF_NEVER = 0
DEREF_IN_SEARCHING = 1
DEREF_FINDING_BASE_OBJ = 2
DEREF_ALWAYS = 3


class Error(Exception):
    """LDAP Error"""


class Client(object):
    """LDAP client."""

    def _encode_filter(self, encoder, filter):
        """Encode a parsed LDAP filter using `encoder'."""
        if isinstance(filter, ldapfilter.AND):
            encoder.enter(0, asn1.ClassContext)
            for term in filter.terms:
                self._encode_filter(encoder, term)
            encoder.leave()
        elif isinstance(filter, ldapfilter.OR):
            encoder.enter(1, asn1.ClassContext)
            for term in filter.terms:
                self._encode_filter(encoder, term)
            encoder.leave()
        elif isinstance(filter, ldapfilter.NOT):
            encoder.enter(2, asn1.ClassContext)
            self._encode_filter(encoder, term)
            encoder.leave()
        elif isinstance(filter, ldapfilter.EQUALS):
            encoder.enter(3, asn1.ClassContext)
            encoder.write(filter.type)
            encoder.write(filter.value)
            encoder.leave()
        elif isinstance(filter, ldapfilter.LTE):
            encoder.enter(5, asn1.ClassContext)
            encoder.write(filter.type)
            encoder.write(filter.value)
            encoder.leave()
        elif isinstance(filter, ldapfilter.GTE):
            encoder.enter(6, asn1.ClassContext)
            encoder.write(filter.type)
            encoder.write(filter.value)
            encoder.leave()
        elif isinstance(filter, ldapfilter.PRESENT):
            encoder.enter(7, asn1.ClassContext)
            encoder.write(filter.type)
            encoder.leave()
        elif isinstance(filter, ldapfilter.APPROX):
            encoder.enter(8, asn1.ClassContext)
            encoder.write(filter.type)
            encoder.write(filter.value)
            encoder.leave()

    def create_search_request(self, dn, filter=None, attrs=None, scope=None,
                              sizelimit=None, timelimit=None, deref=None,
                              typesonly=None, msgid=None):
        """Create a search request. This only supports a very simple AND
        filter."""
        if filter is None:
            filter = '(objectClass=*)'
        if attrs is None:
            attrs = []
        if scope is None:
            scope = SCOPE_SUBTREE
        if sizelimit is None:
            sizelimit = 0
        if timelimit is None:
            timelimit = 0
        if deref is None:
            deref = DEREF_NEVER
        if typesonly is None:
            typesonly = False
        if msgid is None:
            msgid = 1
        parser = ldapfilter.Parser()
        parsed =  parser.parse(filter)
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Sequence)  # LDAPMessage
        encoder.write(msgid)
        encoder.enter(3, asn1.ClassApplication)  # SearchRequest
        encoder.write(dn)
        encoder.write(scope, asn1.Enumerated)
        encoder.write(deref, asn1.Enumerated)
        encoder.write(sizelimit)
        encoder.write(timelimit)
        encoder.write(typesonly, asn1.Boolean)
        self._encode_filter(encoder, parsed)
        encoder.enter(asn1.Sequence)  # attributes
        for attr in attrs:
            encoder.write(attr)
        encoder.leave()  # end of attributes
        encoder.leave()  # end of SearchRequest
        encoder.leave()  # end of LDAPMessage
        result = encoder.output()
        return result

    def parse_message_header(self, buffer):
        """Parse an LDAP header and return the tuple (messageid,
        protocolOp)."""
        decoder = asn1.Decoder()
        decoder.start(buffer)
        self._check_tag(decoder.peek(), asn1.Sequence)
        decoder.enter()
        self._check_tag(decoder.peek(), asn1.Integer)
        msgid = decoder.read()[1]
        tag = decoder.peek()
        self._check_tag(tag, None, asn1.TypeConstructed, asn1.ClassApplication)
        op = tag[0]
        return (msgid, op)

    def parse_search_result(self, buffer):
        """Parse an LDAP search result.

        This function returns a list of search result. Each entry in the list
        is a (msgid, dn, attrs) tuple. attrs is a dictionary with LDAP types
        as keys and a list of attribute values as its values.
        """
        decoder = asn1.Decoder()
        decoder.start(buffer)
        messages = []
        while True:
            tag = decoder.peek()
            if tag is None:
                break
            self._check_tag(tag, asn1.Sequence)
            decoder.enter()  # enter LDAPMessage
            self._check_tag(decoder.peek(), asn1.Integer)
            msgid = decoder.read()[1]  # messageID
            tag = decoder.peek()
            self._check_tag(tag, (4,5), asn1.TypeConstructed, asn1.ClassApplication)
            if tag[0] == 5:
                break
            decoder.enter()  #  SearchResultEntry
            self._check_tag(decoder.peek(), asn1.OctetString)
            dn = decoder.read()[1]  # objectName
            self._check_tag(decoder.peek(), asn1.Sequence)
            decoder.enter()  # enter attributes
            attrs = {}
            while True:
                tag = decoder.peek()
                if tag is None:
                    break
                self._check_tag(tag, asn1.Sequence)
                decoder.enter()  # one attribute
                self._check_tag(decoder.peek(), asn1.OctetString)
                name = decoder.read()[1]  # type
                self._check_tag(decoder.peek(), asn1.Set)
                decoder.enter()  # vals
                values = []
                while True:
                    tag = decoder.peek()
                    if tag is None:
                        break
                    self._check_tag(tag, asn1.OctetString)
                    values.append(decoder.read()[1])
                attrs[name] = values
                decoder.leave()  # leave vals
                decoder.leave()  # leave attribute
            decoder.leave()  # leave attributes
            messages.append((msgid, dn, attrs))
        return messages

    def _check_tag(self, tag, id, typ=None, cls=None):
        """Ensure that `tag' matches with `id', `typ' and `syntax'."""
        if cls is None:
            cls = asn1.ClassUniversal
        if typ is None:
            if id in (asn1.Sequence, asn1.Set):
                typ = asn1.TypeConstructed
            else:
                typ = asn1.TypePrimitive
        if isinstance(id, tuple):
            if tag[0] not in id:
                raise Error, 'LDAP syntax error'
        elif id is not None:
            if tag[0] != id:
                raise Error, 'LDAP syntax error'
        if tag[1] != typ or tag[2] != cls:
            raise Error, 'LDAP syntax error'
