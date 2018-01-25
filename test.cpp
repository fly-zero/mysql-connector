#include <iostream>

#include "mysql.h"
#include "task_queue_thread.h"

class mysql_client
    : public flyzero::mysql
{
public:
    mysql_client(void)
        : thread_(8)
    {
    }

protected:
    void on_net_connect_success(void) override;
    void on_net_connect_closed(void) override;
    void on_client_connect_success(void) override;
    void on_query_result(void) override;

private:
    flyzero::task_queue_thread thread_;
};

void mysql_client::on_net_connect_success(void)
{
    std::cout << "net connect success" << std::endl;
}

void mysql_client::on_net_connect_closed(void)
{
    std::cout << "net connect closed" << std::endl;
}

void mysql_client::on_client_connect_success(void)
{
    std::cout << "client connect success" << std::endl;

    std::string stm("select * from account_types");

    query(stm.c_str(), stm.length());
}

void mysql_client::on_query_result(void)
{
}

int main()
{
    flyzero::epoll ep;

    mysql_client mysql;

    if (!ep.add(mysql, flyzero::epoll::epoll_read | flyzero::epoll::epoll_edge))
        return 1;

    if (!mysql.connect("/var/run/mysqld/mysqld.sock", "flyzero", "129108113", "account_book", 0))
        return 1;

    ep.run(8, -1, nullptr, nullptr);



    return 0;
}
