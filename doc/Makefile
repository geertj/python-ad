#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

XSLTPROC = xsltproc
XSLTFLAGS = --xinclude
STYLESHEET = /usr/share/sgml/docbook/xsl-stylesheets/xhtml/chunk.xsl
MKDIR = mkdir -p
INPUTS = index.xml preface.xml reference.xml license.xml

all: html/index.html

html/index.html: $(INPUTS)
	$(MKDIR) html
	$(XSLTPROC) $(XSLTFLAGS) --output html/index.html $(STYLESHEET) $<
