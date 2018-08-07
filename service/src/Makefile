.PHONY: all clean

LIBS = gloox libpng libqrencode zbar Magick++
CXXFLAGS += -O2 -fPIE -std=c++11 -Wl,-z,relro,-z,now

all: vbot

vbot: vbot.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ -lflite_cmu_us_kal -lflite `pkg-config --cflags --libs $(LIBS)`
	strip $@

clean:
	rm -rf *.o *.dSYM vbot
