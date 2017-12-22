#pragma once

#include <string>
#include <unordered_map>

#include "epoll.h"
#include "file_descriptor.h"
#include "allocator.h"
#include "conststr.h"
#include "hash.h"

namespace flyzero
{

    class mysql : public epoll_listener
    {
        // MYSQL static const fields
        static const uint32_t AUTH_PLUGIN_DATA_PART_1_LENGTH = 8;
        static const uint32_t SCRAMBLE_LENGTH = 20;
        static const uint32_t PROTOCOL_VERSION = 10;
        static const uint32_t SYSTEM_CHARSET_MBMAXLEN = 3;
        static const uint32_t USERNAME_CHAR_LENGTH = 32;
        static const uint32_t NAME_CHAR_LEN = 64;
        static const uint32_t USERNAME_LENGTH = USERNAME_CHAR_LENGTH * SYSTEM_CHARSET_MBMAXLEN;
        static const uint32_t NAME_LEN = NAME_CHAR_LEN * SYSTEM_CHARSET_MBMAXLEN;

        static const uint32_t CLIENT_LONG_PASSWORD = 1;             // new more secure passwords 
        static const uint32_t CLIENT_FOUND_ROWS = 2;                // Found instead of affected rows 
        static const uint32_t CLIENT_LONG_FLAG = 4;                 // Get all column flags 
        static const uint32_t CLIENT_CONNECT_WITH_DB = 8;           // One can specify db on connect 
        static const uint32_t CLIENT_NO_SCHEMA = 16;                // Don't allow database.table.column 
        static const uint32_t CLIENT_COMPRESS = 32;                 // Can use compression protocol 
        static const uint32_t CLIENT_ODBC = 64;                     // Odbc client 
        static const uint32_t CLIENT_LOCAL_FILES = 128;             // Can use LOAD DATA LOCAL 
        static const uint32_t CLIENT_IGNORE_SPACE = 256;            // Ignore spaces before '(' 
        static const uint32_t CLIENT_PROTOCOL_41 = 512;             // New 4.1 protocol 
        static const uint32_t CLIENT_INTERACTIVE = 1024;            // This is an interactive client 
        static const uint32_t CLIENT_SSL = 2048;                    // Switch to SSL after handshake 
        static const uint32_t CLIENT_IGNORE_SIGPIPE = 4096;         // IGNORE sigpipes 
        static const uint32_t CLIENT_TRANSACTIONS = 8192;           // Client knows about transactions 
        static const uint32_t CLIENT_RESERVED = 16384;              // Old flag for 4.1 protocol  
        static const uint32_t CLIENT_RESERVED2 = 32768;             // Old flag for 4.1 authentication 
        static const uint32_t CLIENT_MULTI_STATEMENTS = 1UL << 16;// Enable/disable multi-stmt support 
        static const uint32_t CLIENT_MULTI_RESULTS = 1UL << 17;   // Enable/disable multi-results 
        static const uint32_t CLIENT_PS_MULTI_RESULTS = 1UL << 18;// Multi-results in PS-protocol 
        static const uint32_t CLIENT_PLUGIN_AUTH = 1UL << 19;     // Client supports plugin authentication 
        static const uint32_t CLIENT_CONNECT_ATTRS = 1UL << 20;   // Client supports connection attributes 

        // Enable authentication response packet to be larger than 255 bytes. 
        static const uint32_t CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1UL << 21;

        // Don't close the connection for a connection with expired password. 
        static const uint32_t CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 1UL << 22;

        // Capable of handling server state change information. Its a hint to the
        // server to include the state change information in Ok packet.
        static const uint32_t CLIENT_SESSION_TRACK = 1UL << 23;
        // Client no longer needs EOF packet
        static const uint32_t CLIENT_DEPRECATE_EOF = 1UL << 24;

        static const uint32_t CLIENT_SSL_VERIFY_SERVER_CERT = 1UL << 30;
        static const uint32_t CLIENT_REMEMBER_OPTIONS = 1UL << 31;

        // Note: CLIENT_CAPABILITIES is also defined in sql/client_settings.h.
        // When adding capabilities here, consider if they should be also added to
        // the server's version.
        static const uint32_t CLIENT_CAPABILITIES = CLIENT_LONG_PASSWORD | \
                                                    CLIENT_LONG_FLAG | \
                                                    CLIENT_TRANSACTIONS | \
                                                    CLIENT_PROTOCOL_41 | \
                                                    CLIENT_RESERVED2 | \
                                                    CLIENT_MULTI_RESULTS | \
                                                    CLIENT_PS_MULTI_RESULTS | \
                                                    CLIENT_PLUGIN_AUTH | \
                                                    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | \
                                                    CLIENT_CONNECT_ATTRS | \
                                                    CLIENT_SESSION_TRACK | \
                                                    CLIENT_DEPRECATE_EOF;

        // my static const fields
        static const uint32_t MAX_PACKET_SIZE = 0x40000000U;
        static const uint8_t CHARSET_LATIN1 = 8U;

        // internal types
        using string = std::basic_string<char, std::char_traits<char>, allocator<char> >;
        using alloc_type = std::function<void*(std::size_t)>;
        using dealloc_type = std::function<void(void *)>;

        struct hash
        {
            std::size_t operator()(const string & s) const
            {
                return hash_bytes(s.c_str(), s.length());
            }
        };

        class connection_attributes
        {
            struct hash_string
            {
                std::size_t operator()(const std::string & s) const
                {
                    return hash_bytes(s.c_str(), s.length());
                }
            };

            using attrs_map = std::unordered_map<std::string, std::string, hash_string>;

        public:
            static connection_attributes & get_instance();
            void insert(const char * key, const char * value);
            std::size_t get_attrs_length() const { return attrs_length_; }

        protected:
            connection_attributes();
            ~connection_attributes() = default;

        private:
            attrs_map attrs_;
            std::size_t attrs_length_;
        }; // class connection_attributes

    public:
        explicit mysql(epoll & ep, const alloc_type & alloc = alloc_type(), const dealloc_type & dealloc = dealloc_type());
        bool connect(const conststr & unix_socket, const conststr & user, const conststr & password, const conststr & db, unsigned long client_flag);

    protected:
        void on_read() override;
        void on_write() override;
        void on_close() override;
        int get_fd() const override;
        bool parse_server_auth_packet(const char * data, const std::size_t size);
        void reply_server_auth_packet(const char (&scrambled_password)[SCRAMBLE_LENGTH]);
        void password_scramble(char * dest, const std::size_t size, const char * message, std::size_t message_len) const;

    private:
        epoll & epoll_;
        alloc_type alloc_;
        dealloc_type dealloc_;
        file_descriptor sock_;
        std::size_t npkt_;
        uint32_t client_flag_;
        uint32_t protocol_version_;
        string server_version_;
        uint32_t server_tid_;
        uint32_t server_capabilities_;
        uint32_t server_language_;
        uint32_t server_status_;
        string user_;
        string password_;
        string db_;
    };

}