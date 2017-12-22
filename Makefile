target = mysql_test

all: $(target)

$(target): test.o mysql.o
	g++ $^ -L../libflyzero -o $@ -lflyzero -lcrypto

%.o: %.cpp
	g++ -g3 -c -std=c++14 -I../libflyzero $< -o $@

.PHONY: clean
clean:
	rm test.o mysql.o $(target) -f
