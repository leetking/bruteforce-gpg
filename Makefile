bruteforce-gpg: src/main.c
	gcc -l gpgme -o bruteforce-gpg src/main.c
clean:
	rm --force bruteforce-gpg