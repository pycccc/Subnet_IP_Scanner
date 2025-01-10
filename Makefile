CC = gcc

CFLAGS = -Wall -O2 -g


TARGET = ipscanner

SRCS = main.c fill_packet.c pcap.c
HEADERS = fill_packet.h pcap.h

# Object files

OBJS = $(SRCS:.c=.o)

# Build the target

$(TARGET): $(OBJS)

	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lpcap
# Rule to build .o files from .c files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJS) $(TARGET)
			
			
			
