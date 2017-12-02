#include <iostream>
#include <fstream>
#include <sstream>

#include <string.h>
#include <vector>
#include <string>
#include <map>

#include <memory>
#include <iterator>
#include <algorithm>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

using namespace std;

template<typename T>
class BaseObj;

template <typename EventIdType>
class BaseEvent {
    public:
        using Sender = BaseObj<BaseEvent<EventIdType>>;

    public:
        virtual ~BaseEvent() {}
        EventIdType type() const { return m_type; }
        Sender* sender() const { return m_obj; }

    protected:
        BaseEvent(Sender* obj, const EventIdType type) : m_obj(obj), m_type(type) {}

    protected:
        Sender* m_obj;
        const EventIdType m_type;
};

template<typename EventType>
class BaseObj {
    public:
        using ListenerData = pair<BaseObj*, bool>;

    public:
        BaseObj(BaseObj&& obj) noexcept : m_listeners(obj.m_listeners) {
            obj.m_listeners = nullptr;
        }
        BaseObj& operator = (BaseObj&& obj) noexcept {
            if (this != &obj) {
                clear();
                m_listeners = obj.m_listeners;
                obj.m_listeners = nullptr;
            }
            return *this;
        }
        virtual ~BaseObj() { clear(); }

        void addListener(BaseObj* obj, const bool takeOwnership = false) {
            const auto it = findListener(obj);
            if (it == m_listeners->end()) {
                m_listeners->emplace_back(obj, takeOwnership);
            } else {
                it->second = takeOwnership;
            }
        }
        void removeListener(const BaseObj* obj) {
            const auto it = findListener(obj);
            if (it != m_listeners->end()) {
                if (it->second) {
                    delete it->first;
                }
                m_listeners->erase(it);
            }
        }
        void raiseEvent(EventType* event) const {
            for (ListenerData& l : *m_listeners) {
                l.first->event(event);
            }
        }
        virtual void event(EventType* event) {}

    protected:
        BaseObj() : m_listeners(new vector<ListenerData>) {}
        void clear() {
            if (m_listeners) {
                for (const ListenerData& ld : *m_listeners) {
                    if (ld.second) {
                        delete ld.first;
                    }
                }
                delete m_listeners;
            }
        }

    private:
        typename vector<ListenerData>::iterator findListener(const BaseObj* obj) {
            return find_if(m_listeners->begin(), m_listeners->end(), [obj](const ListenerData& ld) {return obj == ld.first; });
        }

    private:
        vector<ListenerData>* m_listeners;
};

class Packet {
    public:
        Packet() : m_size(0) {}
        Packet(const size_t size) : m_size(size), m_data(size ? new uint8_t[size] : nullptr) {}
        Packet(const void* data, const size_t size) : Packet(data ? size : 0) {
            if (m_data) {
                ::memcpy(m_data.get(), data, size);
            }
        }
        Packet(const Packet& packet) : Packet(packet.size()) {
            ::memcpy(data(), packet.data(), size());
        }
        Packet& operator = (const Packet& packet) {
            if (this != &packet) {
                m_size = packet.m_size;
                m_data.reset(m_size ? new uint8_t[m_size] : nullptr);
                if (data()) {
                    ::memcpy(data(), packet.data(), m_size);
                }
            }
            return *this;
        }
        Packet(Packet&& packet) noexcept : m_size(packet.size()), m_data(packet.m_data.release()) {
            packet.m_size = 0;
        }
        Packet& operator = (Packet&& packet) noexcept {
            if (this != &packet) {
                m_size = packet.m_size;
                packet.m_size = 0;
                m_data.reset(packet.m_data.release());
            }
            return *this;
        }

        size_t size() const { return m_size; }
        uint8_t* data() { return m_data.get(); }
        const uint8_t* data() const { return m_data.get(); }

        uint8_t* begin() { return data(); }
        const uint8_t* begin() const { return data(); }
        uint8_t* end() { return data() + size(); }
        const uint8_t* end() const { return data() + size(); }

    private:
        size_t m_size;
        unique_ptr<uint8_t[]> m_data;
};

enum class Event {
    SockRead,
    HttpRequest,
};

struct StrICmp {
    static int cmp(const string& s1, const string& s2) noexcept {
        const char* it1 = s1.c_str();
        const char* it2 = s2.c_str();
        char ch1;
		char ch2;
        while ((ch1 = ::toupper(*it1)) == (ch2 = ::toupper(*it2)) && ch1 && ch2) {
            ++it1;
            ++it2;
        }
        return ch1 == ch2 ? 0 : (ch1 < ch2 ? -1 : 1);
    }
    int operator () (const string& s1, const string& s2) const noexcept {
        return cmp(s1, s2) < 0;
    }
};

class Socket;

using NameValueCont = map<string, string, StrICmp>;
using MyEventBase = BaseEvent<Event>;
using MyObjBase = BaseObj<MyEventBase>;
using EventPtr = unique_ptr<MyEventBase>;
using BaseObjPtr = unique_ptr<MyObjBase>;
using SocketPtr = unique_ptr<Socket>;

enum class HttpMethod {
    Get,
    Post,
    Put,
    Delete,
};

struct HttpRequest {
    HttpMethod method;
    string uri;
    string version;
    string path;
    NameValueCont headers;
    NameValueCont cookies;
    NameValueCont params;
};

class SockReadEvent : public MyEventBase {
    public:
        SockReadEvent(MyObjBase* sock, Packet packet)
            : MyEventBase(sock, Event::SockRead)
            , m_packet(std::move(packet)) {}
        const Packet& packet() const { return m_packet; }
    private:
        Packet m_packet;
};

class HttpRequestEvent : public MyEventBase {
    public:
        HttpRequestEvent(MyObjBase* s, unique_ptr<HttpRequest> httpRequest)
            : MyEventBase(s, Event::HttpRequest)
            , m_httpRequest(std::move(httpRequest)) {}
        const HttpRequest* request() const { return m_httpRequest.get(); }
        Socket* socket() const { return (Socket*) sender(); }
    private:
        unique_ptr<HttpRequest> m_httpRequest;
};

class Socket : public MyObjBase {
    public:
        using SocketType = int;

    public:
        Socket() {
            m_sock = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        }
        Socket(const SocketType s) : m_sock(s) {}
        Socket(const Socket&) = delete;
        Socket& operator = (const Socket&) = delete;
        Socket(Socket&& s) noexcept : m_sock(s.m_sock) {
            s.m_sock = (SocketType)-1;
        }
        Socket& operator = (Socket&& s) noexcept {
            if (this != &s) {
                close();
                m_sock = s.m_sock;
                s.m_sock = (SocketType)-1;
            }
            return *this;
        }
        ~Socket() { close(); }

        bool listen(const string& addr, uint16_t port) const {
            if (!*this) {
                return false;
            }
            sockaddr_in sa = {};
            sa.sin_family = AF_INET;
            sa.sin_port = ::htons(port);
            if (::inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) <= 0) {
                return false;
            }
            if (::bind(m_sock, (sockaddr*)&sa, sizeof(sa))) {
                return false;
            }
            return ::listen(m_sock, SOMAXCONN) == 0;
        }
        Socket accept() const {
            if (!*this) {
                return Socket((SocketType)-1);
            }
            sockaddr_in sa = {};
            socklen_t len = sizeof(sa);
            Socket s = ::accept(m_sock, (sockaddr*)&sa, &len);
            return s;
        }
        Packet read(bool* isOk = nullptr) const {
            if (!*this) {
                if (isOk) {
                    *isOk = false;
                }
                return Packet();
            }
            constexpr int BuffSize = 4096;
            char buff[BuffSize];
            const int ret = ::recv(m_sock, buff, BuffSize, 0);
            if (isOk) {
                *isOk = ret >= 0;
            }
            return (ret <= 0) ? Packet() : Packet(buff, ret);
        }
        bool write(const Packet& packet) const {
            if (!*this) {
                return false;
            }
            if (packet.size() == 0) {
                return true;
            }
            const int ret = ::send(m_sock, (const char*)packet.data(), packet.size(), 0);
            return ret > 0;
        }
        void close() {
            if (m_sock != (SocketType)-1) {
                ::close(m_sock);
                m_sock = (SocketType) -1;
            }
        }

        SocketType descriptor() const { return m_sock; }
        operator SocketType () const { return m_sock; }
        explicit operator bool() const { return !!*this; }
        bool operator ! () const { return m_sock == (SocketType) -1; }

    private:
        SocketType m_sock;
};

class HttpRequestBuilder : public MyObjBase {
    private:
        enum class State {
            ReadRequestLineState,
            ReadHeadersState,
            GetState,
        };
        enum class RetState {
            Finished,
            NotFinished,
            Error,
        };

    public:
        HttpRequestBuilder(MyObjBase* socket, MyObjBase* server)
            : m_socket(socket)
            , m_server(server)
            , m_state(State::ReadRequestLineState)
            , m_request(new HttpRequest) {}

    private:
        void event(MyEventBase* event) override {
            if (event->type() == Event::SockRead) {
                SockReadEvent *e = (SockReadEvent*)event;
                m_buff.insert(m_buff.end(), (char*)e->packet().begin(), (char*)e->packet().end());

                RetState ret;
                do {
                    ret = process();
                } while (ret == RetState::Finished);
                if (ret == RetState::Error) {
                    cerr << "Bad request" << endl;
                    m_buff.clear();
                    m_state = State::ReadRequestLineState;
                }

            }
        }
        RetState process() {
            switch (m_state) {
                case State::ReadRequestLineState: {
                    return onReadRequestLine();
                }
                case State::ReadHeadersState: {
                    return onReadHeaders();
                }
                case State::GetState: {
                    return onGet();
                }
            }
            return RetState::Error;
        }
        RetState onReadRequestLine() {
            bool hasLine;
            string line = getLine(&hasLine);
            if (!hasLine) {
                return RetState::NotFinished;
            }

            stringstream ss(line);
            {
                string str;
                ss >> str;
                if (StrICmp::cmp(str, "GET") == 0) {
                    m_request->method = HttpMethod::Get;
                } else {
                    return RetState::Error;
                }
            }

            ss >> m_request->uri;
            m_request->path = m_request->uri.substr(0, m_request->uri.find('?'));

            ss >> m_request->version;

            m_request->headers.clear();
            m_state = State::ReadHeadersState;
            return RetState::Finished;
        }
        RetState onReadHeaders() {
            while (true) {
                bool hasLine;
                string line = getLine(&hasLine);
                if (!hasLine) {
                    return RetState::NotFinished;
                }
                if (line.empty()) {
                    break;
                }
                const size_t pos = line.find(':');
                if (pos == string::npos) {
                    return RetState::Error;
                }
                string name = trim(line.substr(0, pos));
                string value = trim(line.substr(pos + 1));
                if (name.empty() || value.empty()) {
                    return RetState::Error;
                }
                if (StrICmp::cmp(name, "COOKIE") == 0) {
                    parseCookies(value);
                }
                m_request->headers[std::move(name)] = std::move(value);
            }
            m_request->params.clear();
            m_state = State::GetState;
            return RetState::Finished;
        }
        RetState onGet() {
            const size_t pos = m_request->uri.find('?');
            if (pos != string::npos) {
                const string params = m_request->uri.substr(pos + 1);
                parseParams(params);
            }

            HttpRequestEvent ev(m_socket, std::move(m_request));
            m_server->event(&ev);

            m_request.reset(new HttpRequest);

            m_state = State::ReadRequestLineState;
            return RetState::Finished;
        }
        void parseCookies(const string& str) const {
            stringstream ss(str);
            while (ss) {
                string cookie;
                std::getline(ss, cookie, ';');
                const size_t i = cookie.find('=');
                if (i == std::string::npos) {
                    continue;
                }
                string name = trim(cookie.substr(0, i));
                if (name.empty()) {
                    continue;
                }
                string value = trim(cookie.substr(i + 1));
                m_request->cookies[std::move(name)] = std::move(value);
            }
        }
        void parseParams(const std::string& params) const {
            stringstream ss(params);
            while(ss) {
                string param;
                getline(ss, param, '&');
                const size_t i = param.find('=');
                if (i == string::npos) {
                    continue;
                }
                string name = trim(param.substr(0, i));
                if (name.empty()) {
                    continue;
                }
                string value = trim(param.substr(i + 1));
                replace(name.begin(), name.end(), '+', ' ');
                replace(value.begin(), value.end(), '+', ' ');
                fromPercentEncoding(&name);
                fromPercentEncoding(&value);
                m_request->params[std::move(name)] = std::move(value);
            }
        }
        string getLine(bool* hasLine) {
            size_t pos = m_buff.find("\r\n");
            if (pos == string::npos) {
                *hasLine = false;
                return string();
            }
            *hasLine = true;
            string ret(m_buff, 0, pos);
            m_buff.erase(0, pos + 2);
            return ret;
        }
        static string trim(const string& s) {
			string::const_iterator beg = s.begin();
			string::const_iterator end = s.end();

			while (beg != end && ::isspace(*beg)) {
				++beg;
			}
			if (beg == end) {
				return string();
			}
			do {
				--end;
			} while (beg != end && ::isspace(*end));

			return string(beg, end + 1);
        }
        static void fromPercentEncoding(std::string* str) {
            std::string::iterator inpIt = str->begin();
            std::string::iterator outIt = inpIt;
            const std::string::iterator end = str->end();
            uint8_t a, b;
            while (inpIt != end) {
                if (*inpIt == '%' && 2 < end - inpIt) {
                    a = *++inpIt;
                    b = *++inpIt;

                    if (a - '0' < 10) a -= '0';
                    else if (a - 'a' < 6) a = a - 'a' + 10;
                    else if (a - 'A' < 6) a = a - 'A' + 10;

                    if (b - '0' < 10) b -= '0';
                    else if (b - 'a' < 6) b = b - 'a' + 10;
                    else if (b - 'A' < 6) b = b - 'A' + 10;

                    *outIt = (char) ((a << 4) | b);
                } else {
                    *outIt = *inpIt;
                }
                ++outIt;
                ++inpIt;
            }
            if (inpIt != outIt)
                str->erase(outIt, end);
        }

    private:
        MyObjBase* m_socket;
        MyObjBase* m_server;
        string m_buff;
        State m_state;
        unique_ptr<HttpRequest> m_request;
};

class SocketThread {
    public:
        SocketThread() : m_exit(false) {}
        SocketThread(const SocketThread&) = delete;

        void run() {
            m_thread = thread(&SocketThread::threadProc, this);
        }
        void addSocket(SocketPtr s) {
            lock_guard<mutex> lk(m_mtx);
	        m_newSocks.emplace_back(std::move(s));
			m_cnd.notify_one();
        }
        void terminate() {
            m_exit.store(true);
            m_cnd.notify_one();
        }
        void wait() {
            if (m_thread.joinable()) {
                m_thread.join();
            }
        }
        size_t size() const {
            lock_guard<mutex> lk(m_mtx);
            return m_sockets.size() + m_newSocks.size();
        }

    private:
        void threadProc() {
            fd_set fd;
			
            while (true) {
                unique_lock<mutex> lk(m_mtx);
                m_cnd.wait(lk, [this] {
					return !m_sockets.empty()
						|| !m_newSocks.empty()
						|| m_exit.load();
				});
                move(
					m_newSocks.begin(),
					m_newSocks.end(),
					back_inserter(m_sockets)
				);
				m_newSocks.clear();
                lk.unlock();

                if (m_exit.load()) {
					cerr << "Exit socket loop" << endl;
                    break;
                }

                FD_ZERO(&fd);
				int maxfd = 0;
                for (const SocketPtr& s : m_sockets) {
					const int d = s->descriptor();
					if (d > maxfd) {
						maxfd = d;
					}
                    FD_SET(d, &fd);
                }
                const int res = ::select(
					maxfd + 1,
					&fd,
					nullptr,
					nullptr,
					nullptr
				);
                if (res < 0) {
                    cerr << "Select error (" << res << ")." << endl;
                } else if (res > 0) {
                    for (const SocketPtr& s : m_sockets) {
                        if (!FD_ISSET(s->descriptor(), &fd)) {
                            continue;
                        }
                        bool isOk = true;
                        Packet p = s->read(&isOk);
                        if (!isOk) {
                            cerr << "Socket read error." << endl;
                            s->close();
                        } else if (p.size() == 0) {
							cerr << "Connection closed." << endl;
                            s->close();
                        } else {
                            SockReadEvent rdEvent(s.get(), std::move(p));
                            s->raiseEvent(&rdEvent);
                        }
                    }
                    m_sockets.erase(
                        remove_if(m_sockets.begin(), m_sockets.end(),
                            [](const SocketPtr& s) {return !*s; }),
                        m_sockets.end()
                    );
                }
            }
        }

    private:
        vector<SocketPtr> m_sockets;
        vector<SocketPtr> m_newSocks;
        thread m_thread;
        mutable mutex m_mtx;
        condition_variable m_cnd;
        atomic_bool m_exit;
};

class ServerBase : MyObjBase {

    public:
        bool run(const string& addr, uint16_t port, const string& dir = "") {
            m_dir = dir;
            m_listener.reset(new Socket);
            if(!m_listener->listen(addr, port)) {
				cerr << "Listen errror." << endl;
                return false;
            }
            for (size_t i = 0; i < 4; ++i) {
                m_workers.emplace_back(new SocketThread);
                m_workers.back()->run();
            }
            while (true) {
                Socket s = m_listener->accept();
                if (!s) {
                    cerr << "Accept error." << endl;
                    break;
                }
				cerr << "Accepted socket" << endl;
                moveToWorker(std::move(s));
            }
            for (unique_ptr<SocketThread>& worker : m_workers) {
                worker->terminate();
                worker->wait();
            }
            return true;
        }

    private:
        size_t minWorkerInd() const {
            size_t ind = -1;
            size_t size = -1;
            for (size_t i = 0; i < m_workers.size(); ++i) {
                const size_t workerSize = m_workers[i]->size();
                if (workerSize == 0) {
                    return i;
                }
                if (workerSize < size) {
                    size = workerSize;
                    ind = i;
                }
            }
            return ind;
        }
        void moveToWorker(Socket s) {
            SocketPtr sockPtr(new Socket(std::move(s)));
			sockPtr->addListener(
				new HttpRequestBuilder(sockPtr.get(), this),
				true
			);
            const size_t ind = minWorkerInd();
            m_workers[ind]->addSocket(std::move(sockPtr));
        }
        void event(BaseEvent<Event>* event) override {
            if (event->type() == Event::HttpRequest) {
                HttpRequestEvent* ev = (HttpRequestEvent*)event;
                string out;
                if (handleRequest(ev->request(), &out)) {
                    out = "HTTP/1.0 200 OK\r\n"
                        "Content-Length: " + to_string(out.size()) + "\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        "\r\n"
                        + out;
                } else {
                    out = "HTTP/1.0 404 Not Found\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n\r\n";
                }
                const Packet p(out.c_str(), out.size());
                if (!ev->socket()->write(p)) {
                    cerr << "Socket write error" << endl;
                    ev->socket()->close();
                }
            }
        }
        bool handleRequest(const HttpRequest* request, string* out) const {
            ifstream fin(m_dir + request->path);
            out->clear();
            if (!fin.is_open()) {
                return false;
            }
            char ch;
            while((ch = fin.get()) != EOF) {
                *out += ch;
            }
            return true;
        }
    private:
        SocketPtr m_listener;
        vector<unique_ptr<SocketThread>> m_workers;
        string m_dir;
};

int main(int argc, char** argv) {

    if(::fork()) {
        return 0;
    }

    setsid();

    string addr;
    string dir;
    uint16_t port = 0;
    if (argc < 7) {
        cerr << "Not enough args" << endl;
		return 1;
    }
    for (char** it = argv + 1; *it; ++it) {
        string opt = *it;
        if (!*++it) {
            break;
        }
        if (opt == "-h") {
            addr = *it;
        } else if (opt == "-p") {
            port = strtoul(*it, nullptr, 10);
        } else if (opt == "-d") {
            dir = *it;
            if (!dir.empty()) {
                const size_t pos = dir.find_last_not_of('/');
                if (pos == string::npos) {
                    dir.clear();
                } else {
                    dir.resize(pos + 1);
                }
            }
        }
    }

    ServerBase serv;
    serv.run(addr, port, dir);

    return 0;
}

