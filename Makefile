CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread
TARGET = autopath-xv
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1

# Check for libnetsnmp
SNMP_EXISTS := $(shell pkg-config --exists netsnmp 2>/dev/null && echo yes)
ifeq ($(SNMP_EXISTS),yes)
    CFLAGS += -DHAVE_SNMP $(shell pkg-config --cflags netsnmp)
    LDFLAGS += $(shell pkg-config --libs netsnmp)
    $(info Building with SNMP support)
else
    $(info Building without SNMP support - install libnetsnmp-dev for SNMP features)
endif

# Source files
SRCS = main.c netutils.c traceroute.c snmp_query.c
OBJS = $(SRCS:.c=.o)


# Main target
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install target
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	gzip -c autopath-xv.1 > $(DESTDIR)$(MANDIR)/autopath-xv.1.gz
	@echo ""
	@echo "Installation complete!"
	@echo "To use without sudo, run: sudo setcap cap_net_raw+ep $(DESTDIR)$(BINDIR)/$(TARGET)"

# Uninstall target
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/autopath-xv.1.gz

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Clean everything including backup files
distclean: clean
	rm -f *~ *.orig

# Build .deb package
deb: clean
	dpkg-buildpackage -us -uc -b

.PHONY: all install uninstall clean distclean deb
