# Makefile for plc_passive_observer
CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -lpcap
TARGET   := plc_passive_observer
SRC      := plc_passive_observer.cpp

.PHONY: all clean install-deps test

all: $(TARGET)

test: scanner_tests.cpp $(SRC)
	$(CXX) $(CXXFLAGS) -o scanner_tests scanner_tests.cpp
	./scanner_tests

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

install-deps:
	# Debian/Ubuntu
	sudo apt-get install -y libpcap-dev
	# Red Hat / CentOS / Fedora
	# sudo dnf install -y libpcap-devel

clean:
	rm -f $(TARGET) scanner_tests
