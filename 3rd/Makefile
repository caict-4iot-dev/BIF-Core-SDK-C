
#Compile 3rd party libraries first, some headers are generated after build, say 3rd/openssl/include
LIBSSL = openssl/libssl.a
LIBSSL_PATH = openssl
LIBCRYPTO = openssl/libcrypto.a

JANSSON = jansson-2.10/build/lib/libjansson.a
JANSSON_PATH = jansson-2.10

#LIBSCRYPT = libscrypt/libscrypt.a
#LIBSCRYPT_PATH = libscrypt

CURL = curl-master/build/lib/libcurl.a
CURL_PATH = curl-master

ED25519 = ed25519-donna/build/libbifchain_ed25519.a
ED25519_PATH = ed25519-donna

LIBSCRYPT = libscrypt/libscrypt.a
LIBSCRYPT_PATH = libscrypt

CUR_DIR = $(shell pwd)

all:add_permission\
    $(LIBSSL) \
    $(LIBCRYPTO) \
    $(JANSSON) \
	$(CURL) \
	$(ED25519) \
	$(LIBSCRYPT)


.PHONY:add_permission
add_permission:
	chmod +x ./openssl/config; \
	[-d ./openssl/include] || cd openssl && ./config;

#sub target 
$(LIBSSL) :
	@echo "*************building openssl ssl now ***************" && cd $(LIBSSL_PATH) && chmod +x config && ./config -fPIC && make -j 4
#$(LIBCRYPTO) :
#	@echo "*************building openssl crypto ***************" && cd $(LIBSSL_PATH) && chmod +x config && ./config  && make -j 4
$(LIBSCRYPT) :
	@echo "*************building LIBSCRYPT now ***************" && cd $(LIBSCRYPT_PATH) && make
$(JANSSON) :
	@echo "*************building jansson now***************" && cd $(JANSSON_PATH) && mkdir build -p;cd build;cmake ../;make -j 4;
$(CURL):
	-@echo "**************building curl now***************" && cd $(CURL_PATH) &&  mkdir build -p&& autoreconf -fi && chmod +x configure && ./configure CPPFLAGS=-fPIC --enable-shared=no --enable-static=yes --disable-ldap --disable-ldaps --without-librtmp --without-brotli --without-ssl --prefix=$(CUR_DIR)/$(CURL_PATH)/build && make -j 4 && make install
$(ED25519):
	@echo "*************building ed25519-donna now***************" && cd $(ED25519_PATH) && mkdir build -p;cd build;cmake ../;make -j 4;
	
clean: \
    LIBSSL_clean \
    LIBCRYPTO_clean \
    LIBSCRYPT_clean \
    JANSSON_clean \
	CURL_clean \
	ED25519_clean
install:
	@echo "No library to install for 3rd"
    
LIBSSL_clean:
	@echo "******************Cleaning openssl now*************" && cd $(LIBSSL_PATH) && make clean -i
LIBCRYPTO_clean:
	@echo "******************Cleaning openssl now*************" && cd $(LIBSSL_PATH) && make clean -i
LIBSCRYPT_clean:
	@echo "******************Cleaning libscrypt now*************" && cd $(LIBSCRYPT_PATH) && make clean -i
CURL_clean:
	@echo "******************Cleaning curl now*************" && cd $(CURL_PATH) && make clean -i && make uninstall -i
JANSSON_clean:
	@echo "******************Cleaning oneTBB now*************" && cd $(JANSSON_PATH)/build && make clean -i
ED25519_clean:
	@echo "******************Cleaning nuraft now*************" && cd $(ED25519_PATH)/build && make clean -i

