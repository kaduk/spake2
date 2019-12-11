all:
	xml2rfc draft-irtf-cfrg-spake2.xml

lint:
	xmllint --format draft-irtf-cfrg-spake2.xml > tmp.xml
	mv tmp.xml draft-irtf-cfrg-spake2.xml
