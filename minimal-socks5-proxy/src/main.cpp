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
                    std::uint8_t wanted_method = 0x00;

                    using namespace boost::log::trivial;
                    boost::system::error_code ec;
                    std::uint8_t socks_ver,  // SOCKS VERSION
                            protocols_len;  // Length of the authentication methods supported
                    std::array<std::uint8_t, max_varied_size> protocols;  // Authentication methods supported

                    // Client connects and sends a greeting...
                    stream_.expires_after(time_limit_);
                    ba::read(stream_, ba::buffer(&socks_ver, sizeof(socks_ver)), ba::transfer_exactly(sizeof(socks_ver)), 0);
                    assert(socks_ver == 0x05);
                    // ...which includes a list  of authentication methods supported.
                    ba::read(stream_, ba::buffer(&protocols_len, sizeof(protocols_len)), ba::transfer_exactly(sizeof(protocols_len)), 0);
                    stream_.expires_after(time_limit_);
                    std::size_t n = ba::async_read(stream_, ba::buffer(protocols, protocols.size()), boost::asio::transfer_exactly(protocols_len), yc[ec], 0);
                    if(ec)
                    {
                        if(ec!=boost::asio::error::eof)
                            throw boost::system::system_error{ec};
                        BOOST_LOG_SEV(log(),info) << "Connection closed";
                        return;
                    }
                    BOOST_LOG_SEV(log(),info) << "Read: " << n;
                    for(std::size_t i = 0; i < n; ++i)
                    {
                        BOOST_LOG_SEV(log(),info)<<"protocol available:"<<std::to_string(protocols[i])<<' ';
                    }

                    std::uint8_t chosen_method = wanted_method;
                    if(std::find(protocols.begin(), protocols.end(), wanted_method) == protocols.end())
                        chosen_method = 0xff;
                    out_buf = {{0x05, chosen_method}};
                    stream_.expires_after(time_limit_);
                    ba::async_write(stream_, ba::buffer(out_buf), yc, 0);
                },{},
                ba::bind_executor(this->cont_executor(),[](std::exception_ptr e)
                {
                    if(e)
                        std::rethrow_exception(e);
                }));
            }
        private:
            std::array<std::uint8_t, max_varied_size> in_buf, out_buf;
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

