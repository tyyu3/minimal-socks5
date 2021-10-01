#include <ce/asio-main.hpp>
#include <ce/charconv.hpp>
#include <ce/format.hpp>
#include <ce/io_context_signal_interrupter.hpp>
#include <ce/socket_session.hpp>
#include <ce/spawn.hpp>
#include <ce/tcp_listener.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/execution/execute.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/static_thread_pool.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/multiprecision/cpp_int.hpp>

//headers I've included in September
#include <boost/asio/streambuf.hpp>
#include <boost/asio.hpp>

#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>

// Differences from asio-advanced:
// - Stackfull Boost.Context-based coroutines are used to improve readability
//   instead of callback functor chains.
// - Detailed I/O error code handling is removed in favor of exception handling
//   to further reduce the size of code, except on first read to demonstrate
//   ability to work without exceptions and still consider clean exit non-exceptional.

namespace ce
{
    namespace
    {
        using bigint = boost::multiprecision::cpp_int;

        using socket_executor_t = ba::strand<ba::io_context::executor_type>;
        using tcp_socket = ba::basic_stream_socket<ba::ip::tcp,socket_executor_t>;
        using tcp_stream = bb::basic_stream<ba::ip::tcp,
            socket_executor_t,
            bb::simple_rate_policy>;

        class calc_session final : public socket_session<calc_session,tcp_stream>
        {
            constexpr static std::size_t number_limit_ = 1024,
                                         bytes_per_second_limit = 1024,
                                         max_varied_size = 256;
            std::map<std::string, const size_t> sizes = {
                {"client greeting", 3}
            };
            constexpr static boost::asio::steady_timer::duration time_limit_ =
                std::chrono::seconds(15);
        public:
            calc_session(ba::io_context::executor_type ex)
                : socket_session<calc_session,tcp_stream>{std::move(ex)}
            {
                stream_.rate_policy().read_limit(bytes_per_second_limit);
            }

            void start_protocol()
            {
                // This captures the pointer to session twice: non-owning as this,
                // and owning as s. We need the owning capture to keep the session
                // alive. Capturing this allows us to omit s-> before accessing
                // any session content at the cost of one additional pointer of state.
                spawn(this->executor(),[this,s=shared_from_this()](auto yc)
                {
                    #define NC_DBG
                    #ifndef NC_DBG
                        std::uint8_t wanted_version = 0x05;
                        std::uint8_t wanted_method = 0x00;
                        std::uint8_t failure_marker = 0xff;
                        std::uint8_t wanted_command = 0x01;
                        std::uint8_t wanted_reserve = 0x00;
                        std::vector<std::uint8_t> wanted_address_type = {0x01, 0x33};
                    #endif
                    #ifdef NC_DBG
                        std::uint8_t wanted_version = '5';
                        std::uint8_t wanted_method = '0';
                        std::uint8_t failure_marker = 'F';
                        std::uint8_t wanted_command = '1';
                        std::uint8_t wanted_reserve = '0';
                        std::vector<std::uint8_t> wanted_address_type = {'1', '3'};

                    #endif

                    using namespace boost::log::trivial;
                    boost::system::error_code ec;

                    // Client connects and sends a greeting...
                    stream_.expires_after(time_limit_);

                    boost::asio::streambuf read_buffer;
                    std::vector<std::uint8_t> read_vector;
                    bool acceptable_response = true;

                    auto bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(2), ec);
                    read_buffer.commit(bytes_transferred);
                    // ...which includes a list of authentication methods supported.
                    bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(last_number(read_buffer)), ec);
                    read_buffer.commit(bytes_transferred);
                    read_vector = make_vector(read_buffer);
                    BOOST_LOG_TRIVIAL(info) << "Read: "<< std::string(read_vector.begin(), read_vector.end()) << std::endl;
                    if((read_vector[0] != wanted_version) || (std::find(read_vector.begin()+2, read_vector.end(), wanted_method) == read_vector.end()))
                        acceptable_response = false;
                    read_buffer.consume(2 + bytes_transferred); // Remove data that was read.

                    // Server chooses one of the methods (or sends a failure response if none of them are acceptable).
                    if(!acceptable_response)
                    {
                        BOOST_LOG_TRIVIAL(info) << "No supported protocol or methods" << std::endl;
                        ba::write(stream_, ba::buffer({wanted_version, failure_marker}), ec);
                        stream_.close();
                    }
                    else
                    {
                        ba::write(stream_, ba::buffer({wanted_version, wanted_method}), ec);
                    }

                    // Client sends a connection request similar to SOCKS4.
                    bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(4), ec);
                    read_buffer.commit(bytes_transferred);
                    read_vector = make_vector(read_buffer);
                    if(read_vector[0] != wanted_version)  // TODO: & other checks here for command and reserve
                    {
                        BOOST_LOG_TRIVIAL(info) << "Bad response "<< std::endl;
                        stream_.close();
                    }
                    if(read_vector[3] == wanted_address_type[0])  // ipv4
                    {
                        bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(4), ec);
                        read_buffer.commit(bytes_transferred);
                        BOOST_LOG_TRIVIAL(info) << "IPv4" << std::endl;
                    }
                    if(read_vector[3] == wanted_address_type[1])  // domain
                    {
                        bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(1), ec);
                        read_buffer.commit(bytes_transferred);
                        bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(last_number(read_buffer)), ec);
                        read_buffer.commit(bytes_transferred);
                        BOOST_LOG_TRIVIAL(info) << "Domain" << std::endl;
                    }
                    bytes_transferred = boost::asio::read(stream_, read_buffer.prepare(2), ec);
                    read_buffer.commit(bytes_transferred);
                    read_vector = make_vector(read_buffer);
                    BOOST_LOG_TRIVIAL(info) << "Read: "<< std::string(read_vector.begin(), read_vector.end()) << std::endl;

                    // TODO: extract IP and port here

                    // read_buffer.consume(???);

                    // boost::asio::io_context m_io_context;
                    // boost::asio::ip::tcp::socket m_stream{m_io_context};
                    // boost::asio::connect(m_stream, boost::asio::ip::tcp::resolver{m_io_context}.resolve(ip, port));

                    // Server sends a response similar to SOCKS4.

                    /* spawn(this->executor(),[this,s=shared_from_this()](auto yc)
                    {
                        // PROXY FROM DST TO CLIENT
                    }*/

                    // PROXY FROM CLIENT TO DST

                },{},
                ba::bind_executor(this->cont_executor(),[](std::exception_ptr e)
                {
                    if(e)
                        std::rethrow_exception(e);
                }));
            }
        private:
            //  std::array<std::uint8_t, max_varied_size> in_buf, out_buf;
            std::vector<std::uint8_t> make_vector(boost::asio::streambuf& streambuf)
            {
              return {boost::asio::buffers_begin(streambuf.data()),
                      boost::asio::buffers_end(streambuf.data())};
            }
            std::uint8_t last_number(boost::asio::streambuf& streambuf)
            {
                return static_cast<std::uint8_t>(make_vector(streambuf).back() - '0'); // NC_DBG: used for symbols
            }

        };
    }

    int main(std::span<const char* const> args)
    {
        if(args.size()<2||args.size()>3)
            throw std::runtime_error(format("Usage: ",args[0]," <listen-port> [threads]"));
        auto port = from_chars<std::uint16_t>(args[1]);
        if(!port||!*port)
            throw std::runtime_error("Port must be in [1;65535]");
        unsigned threads;
        if(args.size()==3){
            auto t = from_chars<unsigned>(args[2]);
            if(!t||!*t)
                throw std::runtime_error("Threads must be a non-zero unsigned integer");
            threads = *t;
        }else
            threads = std::thread::hardware_concurrency();
        using namespace boost::log::trivial;
        BOOST_LOG_TRIVIAL(info) << "Using " << threads << " threads.";
        ba::io_context ctx{int(threads)};
        io_context_signal_interrupter iosi{ctx};
        tcp_listener<calc_session,ba::io_context::executor_type> tl{ctx.get_executor(),*port};
        ba::static_thread_pool tp{threads-1};
        for(unsigned i=1;i<threads;++i)
            bae::execute(tp.get_executor(),[&]{
                ctx.run();
            });
        ctx.run();
        return 0;
    }
}

