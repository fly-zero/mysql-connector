#include "mysql.h"

int main()
{
    flyzero::epoll ep;
    flyzero::mysql mysql(ep);
    mysql.connect("/var/run/mysqld/mysqld.sock", "flyzero", "129108113", "account_book", 0);
    ep.run(8, -1, nullptr, nullptr);
    return 0;
}