.PHONY: all clean

LIBS = gloox libpng libqrencode zbar Magick++
CXXFLAGS += -fPIE -g -std=c++11

all: vbot

vbot: vbot.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ -lflite_cmu_us_kal -lflite `pkg-config --cflags --libs $(LIBS)`
	# strip $@

clean:
	rm -rf *.o *.dSYM vbot
