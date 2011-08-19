# Makefile for mod_fortress


mod_fortress:
	apxs -Wall -i -a -c mod_fortress.c

clean:
	rm -rf mod_fortress.{o,so,slo,lo,la}

