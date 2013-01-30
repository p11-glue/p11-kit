
# Note that nothing here is distributed. It just lives in the git repository
# We copy everything into its final location, and those test files are
# distributed in the tarballs

TRUST = $(top_srcdir)/trust/tests
TOOLS = $(top_srcdir)/tools/tests

prepare-certs:
	cp -v cacert3.der $(TRUST)/anchors
	cp -v cacert3.der $(TRUST)/files
	cp -v cacert3.der $(TOOLS)/files
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3.pem
	openssl x509 -in cacert3.der -inform DER -out $(TOOLS)/files/cacert3.pem
	cat $(TOOLS)/files/cacert3.pem $(TOOLS)/files/cacert3.pem > $(TOOLS)/files/cacert3-twice.pem
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3-trusted.pem \
		-addtrust clientAuth -addtrust serverAuth -addreject emailProtection \
		-setalias "Custom Label"
	cp -v cacert-ca.der $(TRUST)/certificates
	cp -v cacert-ca.der $(TRUST)/files
	openssl x509 -in redhat-newca.der -inform DER -out $(TRUST)/files/distrusted.pem \
		-addreject clientAuth -setalias "Red Hat Is the CA"
	cp -v self-server.der $(TRUST)/files
	cp -v self-signed-with-eku.der $(TRUST)/certificates
	cp -v self-signed-with-ku.der $(TRUST)/certificates
	cp -v testing-ca.der $(TRUST)/anchors
	cp -v testing-server.der $(TRUST)/files

# Rebuild the self-signed certificates. This is almost never necessary and
# will require other changes in the code, mostly here as documentation
build-self-signed:
	openssl req -new -x509 -outform DER -out self-signed-with-eku.der \
		-newkey rsa -keyout /dev/null -nodes -subj /CN=self-signed-with-eku.example.com \
		-config with-eku.conf -set_serial 888 -extensions v3_ca
	openssl req -new -x509 -outform DER -out self-signed-with-ku.der \
		-newkey rsa -keyout /dev/null -nodes -subj /CN=self-signed-with-ku.example.com \
		-config with-ku.conf -set_serial 888 -extensions v3_ca
