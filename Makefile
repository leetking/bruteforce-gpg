GPGMELIBS := $(shell pkg-config --libs gpgme)

bruteforce-gpg: src/main.c bruteforce_gpg.o log.o agent.o
	gcc -o bruteforce-gpg  src/main.c bruteforce_gpg.o log.o agent.o -pthread $(GPGMELIBS)
bruteforce_gpg.o: src/bruteforce_gpg.c src/bruteforce_gpg.h
	gcc -c src/bruteforce_gpg.c -o bruteforce_gpg.o
agent.o: src/agent.c src/agent.h
	gcc -c src/agent.c -o agent.o
log.o: src/log.c src/log.h
	gcc -c src/log.c -o log.o
clean:
	rm --force bruteforce-gpg *.o
install:
	install bruteforce-gpg /usr/local/bin/
