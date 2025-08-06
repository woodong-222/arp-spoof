CXX = g++
CXXFLAGS = -Wall -g
LDLIBS = -lpcap
BUILD = build

all: arp-spoof

$(BUILD):
	mkdir -p $(BUILD)

arp-spoof: $(BUILD)/main.o $(BUILD)/getinfo.o $(BUILD)/arphdr.o $(BUILD)/ethhdr.o $(BUILD)/ip.o $(BUILD)/mac.o
	$(CXX) $^ $(LDLIBS) -o $@

$(BUILD)/main.o: main.cpp addr/mac.h addr/ip.h hdr/ethhdr.h hdr/arphdr.h getinfo.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/getinfo.o: getinfo.cpp getinfo.h addr/mac.h addr/ip.h hdr/ethhdr.h hdr/arphdr.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/arphdr.o: hdr/arphdr.cpp hdr/arphdr.h addr/mac.h addr/ip.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/ethhdr.o: hdr/ethhdr.cpp hdr/ethhdr.h addr/mac.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/ip.o: addr/ip.cpp addr/ip.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/mac.o: addr/mac.cpp addr/mac.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf arp-spoof $(BUILD)
