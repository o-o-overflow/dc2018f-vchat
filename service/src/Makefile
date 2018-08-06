.PHONY: all clean

CXXFLAGS += -fPIE -g -std=c++11

all: vbot

vbot: vbot.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ -lgloox -lflite_cmu_us_kal -lflite -lpng -lqrencode
	# strip $@

clean:
	rm -rf *.o *.dSYM vbot
