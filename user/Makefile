# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = snap
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
