# Compiler
CC=gcc

# Paths
OPENSSL= ../openssl
KYBER= ../handout/kyber512
#SUBMISSION=/home/shaundsz/lab-1-Shaundsz/submission

# Include and Library Directories
INCLUDE=-I$(OPENSSL)/include -I$(KYBER)
LIBS=-L$(OPENSSL) -L$(KYBER)
KEXTRAS=$(KYBER)/fips202.c $(KYBER)/randombytes.c

# Flags
CFLAGS=$(INCLUDE) $(LIBS) -ldl -lpthread
KYBERFLAGS=$(CFLAGS) -lkyber512_clean

# Additional sources and libraries for kyber_test
SOURCES= kyber_test.c ../handout/kyber512/fips202.c ../handout/kyber512/randombytes.c
KYBER_LIBS=../handout/kyber512/libkyber512_clean.a -lssl -lcrypto

# Targets
all: AES_test RSA_test Kyber_test_mod1

AES_test:
	$(CC) $(CFLAGS) -o AES_test AES_test.c $(OPENSSL)/libcrypto.a

RSA_test:
	$(CC) $(CFLAGS) -o RSA_test RSA_test.c $(OPENSSL)/libcrypto.a

Kyber_test_mod1:
	$(CC) $(CFLAGS) -o Kyber_test_mod1 Kyber_test_mod1.c $(KEXTRAS) $(OPENSSL)/libcrypto.a $(KYBER)/libkyber512_clean.a -ldl -lkyber512_clean

clean:
	rm -f AES_test RSA_test Kyber_test_mod1 client_test kyber_test

# Generates the outputs aes.txt, rsa.txt, and kyber.txt for each test (p1 target)
p1: AES_test RSA_test Kyber_test_mod1
	@echo "Running AES Test..."
	@$ ./AES_test > $ aes.txt
	@echo "Running RSA Test..."
	@$ ./RSA_test > $ rsa.txt
	@echo "Running Kyber Test..."
	@$ ./Kyber_test_mod1 > $ kyber.txt

# Secure communication client and Kyber test (p3 target)
p3: client kyber_test
	@echo "Running RSA and AES secure communication..."
	./client_test
	@echo "Running Kyber secure test..."
	./kyber_test

# Compile the client_test executable
client: client_test.c
	$(CC) $(CFLAGS) -o client_test client_test.c -L$(OPENSSL) -L$(KYBER) -lcrypto -lssl -ldl -lkyber512_clean

# Compile the kyber_test executable
kyber_test: $(SOURCES)
	$(CC) $(CFLAGS) -o kyber_test $(SOURCES) -I$(KYBER) $(KYBER_LIBS)
