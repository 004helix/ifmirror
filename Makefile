CC = gcc
LD = gcc
CFLAGS = -Wall
#CFLAGS = -Wall -g
LDFLAGS = 

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,build/%.o,$(SRC))

all: ifraw iftap

ifraw: build/ifraw.o
	$(LD) -o $@ build/ifraw.o $(LDFLAGS)

iftap: build/iftap.o
	$(LD) -o $@ build/iftap.o $(LDFLAGS)

-include $(OBJ:.o=.d)

$(OBJ): build/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o build/$*.o
	@$(CC) $(CFLAGS) -MM $< -MF build/$*.d
	@sed -i build/$*.d -e 's,\($*\)\.o[ :]*,build/\1.o: ,g'

clean:
	rm -rf $(EXE) build/*.o build/*.d
