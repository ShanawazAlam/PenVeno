CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
PKG_CONFIG = pkg-config
DEPS = gtkmm-3.0 openssl
CXXFLAGS += $(shell $(PKG_CONFIG) --cflags $(DEPS))
LDFLAGS += $(shell $(PKG_CONFIG) --libs $(DEPS))

TARGET = PenVeno
SRC = PenVeno.c++

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.bak

run: $(TARGET)
	./$(TARGET)

screenshots: $(TARGET)
	mkdir -p docs/screenshots
	xvfb-run -a ./$(TARGET) --generate-screenshots docs/screenshots

install: $(TARGET)
	install -d /usr/local/bin
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	install -d /usr/local/share/applications
	install -m 644 PenVeno.desktop /usr/local/share/applications/ 2>/dev/null || true

.PHONY: all clean run install
