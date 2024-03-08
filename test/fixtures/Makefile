all: \
	cert.key.h \
	cert.crt.h

%.h: %
	xxd -i $^ > $@

%.key:
	openssl genpkey \
		-algorithm rsa \
		-out $@

%.crt: %.cnf %.key
	openssl req \
		-x509 \
		-noenc \
		-days 365 \
		-config $*.cnf \
		-key $*.key \
		-out $@
