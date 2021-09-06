CC=gcc -pedantic -Wall -Wextra -g

all: dumper

dumper: authenticode_dumper.c authenticode.o structs.o helper.o certificate.o countersignature.o
	$(CC) $^ -o $@ -lssl -lcrypto

certificate.o: ../src/certificate.c ../src/certificate.h
	$(CC) -c $<

authenticode.o: ../src/authenticode.c ../src/authenticode.h
	$(CC) -c $<

countersignature.o: ../src/countersignature.c ../src/countersignature.h
	$(CC) -c $<

structs.o: ../src/structs.c ../src/structs.h
	$(CC) -c $<

helper.o: ../src/helper.c ../src/helper.h
	$(CC) -c $<

clean:
	rm *.o dumper