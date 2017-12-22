
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cassert>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <algorithm>
#include <memory>

#include <openssl/sha.h>

#include "mysql.h"
#include "file_descriptor.h"


namespace flyzero
{

    static const std::size_t SHA1_HASH_SIZE = 20;

    static uint16_t uint2korr(const char * const a)
    {
        assert(a);
        return *reinterpret_cast<const uint16_t *>(a);
    }

    static uint32_t uint3korr(const char * const a)
    {
        assert(a);
        return uint32_t(uint32_t(a[0]) + (uint32_t(a[1]) << 8) + (uint32_t(a[2]) << 16));
    }

    static uint32_t uint4korr(const char * a)
    {
        assert(a);
        return *reinterpret_cast<const uint32_t *>(a);
    }

    void int4store(unsigned char * t, uint32_t a)
    {
        *reinterpret_cast<uint32_t *>(t) = a;
    }

    static const char * strend(const char * s)
    {
        assert(s);
        while (*s) ++s;
        return s;
    }

    static void sha1_hash(uint8_t * digest, const char * buff, std::size_t size)
    {
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, buff, size);
        SHA1_Final(digest, &ctx);
    }

    static void sha1_hash(uint8_t * digest, const char * buff1, std::size_t size1, const char * buff2, std::size_t size2)
    {
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, buff1, size1);
        SHA1_Update(&ctx, buff2, size2);
        SHA1_Final(digest, &ctx);
    }

    static void mysql_crypt(char *to, const uint8_t *s1, const uint8_t *s2, const uint len)
    {
        const auto s1_end = s1 + len;
        while (s1 < s1_end)
            *to++ = *s1++ ^ *s2++;
    }

    // this function is not thread safe
    // TODO: make a thread-safe version
    const char * get_pid_str()
    {
        static char buff[24];
        if (buff[0] != '0')
        {
            const auto pid = getpid();
            sprintf(buff, "%d", pid);
        }
        return buff;
    }

    std::size_t get_int_mysql_storage_size(const std::size_t i)
    {
        if (i < 251ULL)
            return 1;
        if (i < 65536ULL)
            return 3;
        if (i < 16777216ULL)
            return 4;
        return 9;
    }

    mysql::connection_attributes::connection_attributes()
        : attrs_length_(0)
    {
        insert("_os", "Linux");                 // TODO: try a diffrent os string
        insert("_client_name", "libmysql");     // TODO: try a diffrent client name string
        insert("_pid", get_pid_str());
        insert("_client_version", "6.1.11");    // TODO: try a diffrent version string
        insert("_platform", "x86_64");          // TODO: get platform dynamic or by MACRO
    }

    mysql::connection_attributes& mysql::connection_attributes::get_instance()
    {
        static connection_attributes attris;
        return attris;
    }

    void mysql::connection_attributes::insert(const char * key, const char * value)
    {
        attrs_.emplace(key, value);
        const auto key_len = strlen(key);
        const auto val_len = strlen(value);
        attrs_length_ += get_int_mysql_storage_size(key_len) + key_len + get_int_mysql_storage_size(val_len) + val_len;
    }

    mysql::mysql(epoll & ep, const alloc_type & alloc /* = alloc_type() */, const dealloc_type & dealloc /* = dealloc_type() */)
        : epoll_(ep)
        , alloc_(alloc)
        , dealloc_(dealloc)
        , npkt_(0)
        , client_flag_(CLIENT_CAPABILITIES)
        , protocol_version_(0)
        , server_version_(allocator<char>(alloc, dealloc))
        , server_tid_(0)
        , server_capabilities_(0)
        , server_language_(0)
        , server_status_(0)
        , user_(allocator<char>(alloc, dealloc))
        , password_(allocator<char>(alloc, dealloc))
        , db_(allocator<char>(alloc, dealloc))
    {
    }

    bool mysql::connect(const conststr & unix_socket, const conststr & user, const conststr & password, const conststr & db, unsigned long client_flag)
    {
        sock_ = file_descriptor(socket(AF_UNIX, SOCK_STREAM, 0));

        if (!sock_)
        {
            // TODO: create socket error
            return false;
        }

        if (!sock_.set_nonblocking())
        {
            // TODO: set nonblocking error
            return false;
        }

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, unix_socket.c_str(), sizeof addr.sun_path);

        const auto res = ::connect(sock_.get(), reinterpret_cast<sockaddr *>(&addr), sizeof addr);

        if (res == -1)
        {
            // TODO: connect error
            return false;
        }

        client_flag_ |= client_flag;
        user_.assign(user.c_str(), user.length());
        password_.assign(password.c_str(), password.length());
        db_.assign(db_.c_str(), db_.length());

        epoll_.add(*this, epoll::epoll_read | epoll::epoll_close | epoll::epoll_edge);

        return false;
    }

    void mysql::on_read()
    {
        char buffer[1024];
        std::size_t pos = 0;
        ssize_t nread;
        while ((nread = ::read(sock_.get(), buffer + pos, sizeof buffer - pos)) > 0) pos += nread;
        if (nread == -1 && (EAGAIN == errno || errno == EWOULDBLOCK))
        {
            // TODO: parse packet
            parse_server_auth_packet(buffer, pos);
        }
        else
        {
            // TODO: connection is closed
            epoll_.remove(*this);
            sock_.close();
        }
    }

    void mysql::on_write()
    {
    }

    void mysql::on_close()
    {
        std::cout << "close connection" << std::endl;
    }

    int mysql::get_fd() const
    {
        return sock_.get();
    }

    bool mysql::parse_server_auth_packet(const char * data, const std::size_t size)
    {
        if (size < 4)
        {
            // TODO: mysql server first packet error
            return false;
        }

        // get packet length and sequence number
        const auto pkt_len = uint3korr(data);
        const auto pkt_seq = uint32_t(data[3]);

        // check sequence number
        if (pkt_seq != 0)
        {
            // TODO: mysql server first packet error
            return false;
        }

        // increase packet counter
        ++npkt_;

        if (size < pkt_len + 4)
        {
            // TODO: mysql server first packet error
            return false;
        }

        auto p = data + 4;

        // get protocol version
        protocol_version_ = uint32_t(p[0]);

        // check protocol version
        if (protocol_version_ != PROTOCOL_VERSION)
        {
            // TODO: prtocol version error
            return false;
        }

        // get mysql version string
        const auto server_version = ++p;
        p = strend(p);
        server_version_.assign(server_version, p);

        // get server thread id
        server_tid_ = uint4korr(p + 1);

        p += 5;

        // get scramble data part 1
        const auto scramble_part_1 = p;
        const auto scramble_part_1_len = AUTH_PLUGIN_DATA_PART_1_LENGTH;

        p += scramble_part_1_len + 1;

        const auto end = data + size;

        if (end < p + 18)
        {
            // TODO: mysql server first packet error
            return false;
        }

        // get server attributes
        server_capabilities_ = uint2korr(p);
        server_language_ = p[2];
        server_status_ = uint2korr(p + 3);
        server_capabilities_ |= uint2korr(p + 5) << 16;
        const uint32_t total_scrable_len = p[7];

        p += 18;

        if (end < p + SCRAMBLE_LENGTH - AUTH_PLUGIN_DATA_PART_1_LENGTH + 1)
        {
            // TODO: mysql server first packet error
            return false;
        }

        // get scramble data part 2
        const auto scramble_part_2 = p;
        const auto scramble_part_2_len = total_scrable_len - scramble_part_1_len - 1;

        // construct scramble message
        char scramble_message[SCRAMBLE_LENGTH], scrambled_password[SCRAMBLE_LENGTH];
        std::copy(scramble_part_1, scramble_part_1 + scramble_part_1_len, scramble_message);
        std::copy(scramble_part_2, scramble_part_2 + scramble_part_2_len, scramble_message + scramble_part_1_len);

        // scramble password
        password_scramble(scrambled_password, SCRAMBLE_LENGTH, scramble_message, SCRAMBLE_LENGTH);

        // reply server auth packet
        reply_server_auth_packet(scrambled_password);

        return true;
    }

    void mysql::reply_server_auth_packet(const char(& scrambled_password)[SCRAMBLE_LENGTH])
    {
        // calculate buffer size
        const auto connect_attrs_len = server_capabilities_ & CLIENT_CONNECT_ATTRS ? connection_attributes::get_instance().get_attrs_length() : 0;
        const auto buff_size = 4 + 33 + USERNAME_LENGTH + SCRAMBLE_LENGTH + 9 + NAME_LEN + NAME_LEN + connect_attrs_len + 9;
        std::unique_ptr<char[], dealloc_type> buffer(reinterpret_cast<char *>(alloc_(buff_size)), dealloc_);

        auto p = buffer.get() + 4;

        assert(client_flag_ & CLIENT_PROTOCOL_41);  // use 4.1 protocol

        assert(buff_size >= 32);    // 4.1 protocol has a 32 byte option flag

        int4store(reinterpret_cast<unsigned char *>(p), client_flag_);
        int4store(reinterpret_cast<unsigned char *>(p + 4), MAX_PACKET_SIZE);
        reinterpret_cast<uint8_t *>(p)[8] = CHARSET_LATIN1;
        memset(buffer.get() + 9, 0, 32 - 9);

        p += 32;
    }

    void mysql::password_scramble(char * dest, const std::size_t size, const char * message, const std::size_t message_len) const
    {
        assert(!password_.empty());

        uint8_t stage1[SHA1_HASH_SIZE], stage2[SHA1_HASH_SIZE];
        sha1_hash(stage1, password_.c_str(), password_.length());
        sha1_hash(stage2, reinterpret_cast<char *>(stage1), SHA1_HASH_SIZE);
        sha1_hash(reinterpret_cast<uint8_t*>(dest), message, message_len, reinterpret_cast<char *>(stage2), SHA1_HASH_SIZE);
        mysql_crypt(dest, reinterpret_cast<uint8_t*>(dest), stage1, size);
    }

}
