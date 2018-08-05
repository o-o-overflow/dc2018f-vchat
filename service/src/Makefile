.PHONY: all clean

CXXFLAGS += -fPIE -g -std=c++11

all: vbot

vbot: vbot.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ -lgloox
	# strip $@

clean:
	rm -rf *.o *.dSYM vbot
