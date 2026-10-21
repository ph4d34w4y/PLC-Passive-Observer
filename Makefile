# Makefile for plc_passive_observer
CXX       := g++
CXXFLAGS  := -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wshadow
LDLIBS    := -lpcap
SANFLAGS  := -std=c++17 -g -O1 -Wall -Wextra -fsanitize=address,undefined \
             -fno-omit-frame-pointer -fno-sanitize-recover=all
TARGET    := plc_passive_observer
SRC       := plc_passive_observer.cpp

.PHONY: all clean install-deps test asan-test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

# Unit tests include the program source and call the packet parser directly.
test: scanner_tests.cpp $(SRC)
	$(CXX) $(CXXFLAGS) -o scanner_tests scanner_tests.cpp $(LDLIBS)
	./scanner_tests

# Same tests with AddressSanitizer + UBSan: any out-of-bounds read is fatal.
asan-test: scanner_tests.cpp $(SRC)
	$(CXX) $(SANFLAGS) -o scanner_tests_asan scanner_tests.cpp $(LDLIBS)
	./scanner_tests_asan

install-deps:
	# Debian/Ubuntu
	sudo apt-get install -y g++ make libpcap-dev
	# Red Hat / CentOS / Fedora
	# sudo dnf install -y gcc-c++ make libpcap-devel

clean:
	rm -f $(TARGET) scanner_tests scanner_tests_asan
