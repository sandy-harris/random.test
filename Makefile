random.rfc: random.rfc.c random_init.h
	gcc -g -Wall -fno-omit-frame-pointer random.rfc.c -o random.rfc
	@if which shred > /dev/null ;		\
	then					\
		shred -uz random_init.h ;	\
	else					\
		rm random_init.h ;		\
		echo Please install shred\(1\) for secure file deletion\! ; \
	fi ;					\
	./random.rfc

# make all the #ifdefs in the code succeed
random.all: random.rfc.c random_init.h
	gcc -Wall -DEMULATE_HW_RNG -DCONSERVATIVE -DHAVE_64_BIT random.rfc.c -o random.all
	./random.all

random_init.h: gen_random_init
	./gen_random_init > random_init.h

gen_random_init: gen_random_init.c
	gcc -Wall gen_random_init.c -o gen_random_init

clean:
	rm -f *.o random_init.h gen_random_init random.rfc random.all clang_out

lint : random.rfc.c random_init.h
	splint -compdef -shiftnegative -statictrans -kepttrans -predboolint -paramuse random.rfc.c

clang : random.rfc.c random_init.h
	clang -Wall random.rfc.c -o clang_out
	./clang_out