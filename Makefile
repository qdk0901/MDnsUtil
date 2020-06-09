.PHONY:	clean

CFLAGS = -lstdc++

SOURCES = main.cpp MDnsUtil.cpp

test: $(SOURCES)
	$(CC) -o test $(SOURCES) $(CFLAGS)

clean:
	-rm test