all: mybuf use_llhttp

mybuf: utmybuf.c ut.c mybuf.c 
	gcc -g -O0 -o $@ $^

use_llhttp: use_llhttp.c llhttp/api.c llhttp/http.c llhttp/llhttp.c ut.c mybuf.c 
	gcc -g -O0 -o $@ $^

clean:
	rm -f mybuf use_llhttp
