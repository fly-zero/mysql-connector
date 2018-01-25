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

        enum client_capability
        {
            CLIENT_LONG_PASSWORD    = 1,            // new more secure passwords 
            CLIENT_FOUND_ROWS       = 2,            // Found instead of affected rows 
            CLIENT_LONG_FLAG        = 4,            // Get all column flags 
            CLIENT_CONNECT_WITH_DB  = 8,            // One can specify db on connect 
            CLIENT_NO_SCHEMA        = 16,           // Don't allow database.table.column 
            CLIENT_COMPRESS         = 32,           // Can use compression protocol 
            CLIENT_ODBC             = 64,           // Odbc client 
            CLIENT_LOCAL_FILES      = 128,          // Can use LOAD DATA LOCAL 
            CLIENT_IGNORE_SPACE     = 256,          // Ignore spaces before '(' 
            CLIENT_PROTOCOL_41      = 512,          // New 4.1 protocol 
            CLIENT_INTERACTIVE      = 1024,         // This is an interactive client 
            CLIENT_SSL              = 2048,         // Switch to SSL after handshake 
            CLIENT_IGNORE_SIGPIPE   = 4096,         // IGNORE sigpipes 
            CLIENT_TRANSACTIONS     = 8192,         // Client knows about transactions 
            CLIENT_RESERVED         = 16384,        // Old flag for 4.1 protocol  
            CLIENT_RESERVED2        = 32768,        // Old flag for 4.1 authentication 
            CLIENT_MULTI_STATEMENTS = 1UL << 16,    // Enable/disable multi-stmt support 
            CLIENT_MULTI_RESULTS    = 1UL << 17,    // Enable/disable multi-results 
            CLIENT_PS_MULTI_RESULTS = 1UL << 18,    // Multi-results in PS-protocol 
            CLIENT_PLUGIN_AUTH      = 1UL << 19,    // Client supports plugin authentication 
            CLIENT_CONNECT_ATTRS    = 1UL << 20,    // Client supports connection attributes 
            
            // Enable authentication response packet to be larger than 255 bytes. 
            CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1UL << 21,

            // Don't close the connection for a connection with expired password. 
            CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 1UL << 22,

            // Capable of handling server state change information. Its a hint to the
            // server to include the state change information in Ok packet.
            CLIENT_SESSION_TRACK = 1UL << 23,

            // Client no longer needs EOF packet
            CLIENT_DEPRECATE_EOF = 1UL << 24,

            CLIENT_SSL_VERIFY_SERVER_CERT = 1UL << 30,
            CLIENT_REMEMBER_OPTIONS = 1UL << 31,
        };

        enum server_command
        {
            COM_SLEEP,
            COM_QUIT,
            COM_INIT_DB,
            COM_QUERY,
            COM_FIELD_LIST,
            COM_CREATE_DB,
            COM_DROP_DB,
            COM_REFRESH,
            COM_SHUTDOWN,
            COM_STATISTICS,
            COM_PROCESS_INFO,
            COM_CONNECT,
            COM_PROCESS_KILL,
            COM_DEBUG,
            COM_PING,
            COM_TIME,
            COM_DELAYED_INSERT,
            COM_CHANGE_USER,
            COM_BINLOG_DUMP,
            COM_TABLE_DUMP,
            COM_CONNECT_OUT,
            COM_REGISTER_SLAVE,
            COM_STMT_PREPARE,
            COM_STMT_EXECUTE,
            COM_STMT_SEND_LONG_DATA,
            COM_STMT_CLOSE,
            COM_STMT_RESET,
            COM_SET_OPTION,
            COM_STMT_FETCH,
            COM_DAEMON,
            COM_BINLOG_DUMP_GTID,
            COM_RESET_CONNECTION,

            // Must be last
            COM_END
        };

        enum client_status
        {
            CLIENT_WAIT_AUTH_INFO,
            CLIENT_WAIT_AUTH_RESULT,
            CLIENT_CONNECTED,

            // Must be last
            CLIENT_STATUS_END
        };

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
        using on_status_handler = std::function<client_status (mysql *, const char *, std::size_t)>;

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
            char * store(char * dst) const;

        protected:
            connection_attributes();
            ~connection_attributes() = default;

        private:
            attrs_map attrs_;
            std::size_t attrs_length_;
        }; // class connection_attributes

    public:
        explicit mysql(const alloc_type & alloc = malloc, const dealloc_type & dealloc = free);
        virtual ~mysql(void) = default;
        bool connect(const conststr & unix_socket, const conststr & user, const conststr & password, const conststr & db, const uint32_t client_flag);
        int query(const char * stm, uint32_t length);

        virtual void on_net_connect_success(void) = 0;
        virtual void on_net_connect_closed(void) = 0;
        virtual void on_client_connect_success(void) = 0;
        virtual void on_query_result(void) = 0;

    protected:
        void on_read(void) override final;
        void on_write(void) override final;
        void on_close(void) override final;
        int get_fd(void) const override final;
        bool parse_server_auth_packet(const char * data, const std::size_t size, char (&scrambled_passord_buff)[SCRAMBLE_LENGTH]);
        bool reply_server_auth_packet(const char (&scrambled_password)[SCRAMBLE_LENGTH]);
        void password_scramble(char * dest, const std::size_t size, const char * message, std::size_t message_len) const;
        static client_status on_server_auth_info(mysql* obj, const char* data, const std::size_t size);
        static client_status on_auth_result(mysql * obj, const char * data, const std::size_t size);
        static client_status on_client_connected(mysql * obj, const char * data, const std::size_t size);
        static client_status on_wait_query_result(mysql * obj, const char * data, const std::size_t size);

    private:
        alloc_type alloc_;
        dealloc_type dealloc_;
        file_descriptor sock_;
        std::size_t npkt_;
        client_status client_status_;
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
        bool query_flag_;
        static on_status_handler handlers_[CLIENT_STATUS_END];
    };

}
