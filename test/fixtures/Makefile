all: \
	cert.pem.h \
	cert.key.h

%.h: %
	xxd -i $^ > $@

%.key:
	openssl genpkey \
		-algorithm rsa \
		-out $@

%.pem: %.cnf %.key
	openssl req \
		-x509 \
		-noenc \
		-days 365 \
		-config $*.cnf \
		-key $*.key \
		-out $*.pem
