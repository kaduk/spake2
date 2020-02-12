all: draft-irtf-cfrg-spake2.txt draft-irtf-cfrg-spake2.html

draft-irtf-cfrg-spake2.txt: draft-irtf-cfrg-spake2.xml
	xml2rfc --text draft-irtf-cfrg-spake2.xml

draft-irtf-cfrg-spake2.html: draft-irtf-cfrg-spake2.xml
	xml2rfc --html draft-irtf-cfrg-spake2.xml
