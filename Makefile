target = mysql_test

all: $(target)

$(target): test.o mysql.o
	g++ $^ -Llibflyzero -o $@ -lflyzero -lcrypto -lpthread

%.o: %.cpp
	g++ -g3 -c -std=c++14 -Ilibflyzero $< -o $@

.PHONY: clean
clean:
	rm test.o mysql.o $(target) -f
