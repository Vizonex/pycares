# The great benefit of this approch is that we can also acess this
# theoretically from cython as well...
# this technique would be simillar to the way numpy works

from . cimport cares
from cpython.bool cimport PyBool_FromLong
from cpython.bytes cimport PyBytes_AsString, PyBytes_FromStringAndSize, PyBytes_AS_STRING, PyBytes_FromString
from cpython.exc cimport PyErr_NoMemory, PyErr_SetObject
from cpython.long cimport PyLong_FromLong, PyLong_AsDouble
from cpython.mem cimport PyMem_Malloc, PyMem_Free, PyMem_Calloc
from cpython.object cimport PyObject
from cpython.unicode cimport PyUnicode_Check
from cpython.sequence cimport PySequence_Check
from cpython.tuple cimport PyTuple_GET_ITEM
cimport cython


from .errno cimport pycares_err_name, pycares_strerror
import socket

from libc cimport math
from libc.stdint cimport uint64_t
from libc.string cimport memset, memcpy


cdef AF_INET = socket.AF_INET
cdef AF_INET6 = socket.AF_INET6

del socket


cdef extern from "Python.h":
    """
/* Custom Macros because cython hates PyObjects in VA-ARGS */

#define pycares_socket_cb (cb, socket_fd, readable, writeable) \
    PyObject_CallFunctionObjArgs(cb, socket_fd, readable, writeable)

// Cython has trouble this a macro solves everything
#define GET_MEM_ADDRESS(ptr) *ptr

    """
    PyObject* pycares_socket_cb(
        object cb, 
        object socket_fd, 
        object readable, 
        object writeable
    # raise null if user throws exception
    # this way the program will end sooner 
    # than later
    ) except NULL

    char* GET_MEM_ADDRESS(char**)



# Flag values
ARES_FLAG_USEVC = cares._ARES_FLAG_USEVC
ARES_FLAG_PRIMARY = cares._ARES_FLAG_PRIMARY
ARES_FLAG_IGNTC = cares._ARES_FLAG_IGNTC
ARES_FLAG_NORECURSE = cares._ARES_FLAG_NORECURSE
ARES_FLAG_STAYOPEN = cares._ARES_FLAG_STAYOPEN
ARES_FLAG_NOSEARCH = cares._ARES_FLAG_NOSEARCH
ARES_FLAG_NOALIASES = cares._ARES_FLAG_NOALIASES
ARES_FLAG_NOCHECKRESP = cares._ARES_FLAG_NOCHECKRESP
ARES_FLAG_EDNS = cares._ARES_FLAG_EDNS
ARES_FLAG_NO_DFLT_SVR = cares._ARES_FLAG_NO_DFLT_SVR

# Nameinfo flag values
ARES_NI_NOFQDN = cares._ARES_NI_NOFQDN
ARES_NI_NUMERICHOST = cares._ARES_NI_NUMERICHOST
ARES_NI_NAMEREQD = cares._ARES_NI_NAMEREQD
ARES_NI_NUMERICSERV = cares._ARES_NI_NUMERICSERV
ARES_NI_DGRAM = cares._ARES_NI_DGRAM
ARES_NI_TCP = cares._ARES_NI_TCP
ARES_NI_UDP = cares._ARES_NI_UDP
ARES_NI_SCTP = cares._ARES_NI_SCTP
ARES_NI_DCCP = cares._ARES_NI_DCCP
ARES_NI_NUMERICSCOPE = cares._ARES_NI_NUMERICSCOPE
ARES_NI_LOOKUPHOST = cares._ARES_NI_LOOKUPHOST
ARES_NI_LOOKUPSERVICE = cares._ARES_NI_LOOKUPSERVICE
ARES_NI_IDN = cares._ARES_NI_IDN
ARES_NI_IDN_ALLOW_UNASSIGNED = cares._ARES_NI_IDN_ALLOW_UNASSIGNED
ARES_NI_IDN_USE_STD3_ASCII_RULES = cares._ARES_NI_IDN_USE_STD3_ASCII_RULES

# Bad socket
ARES_SOCKET_BAD = cares._ARES_SOCKET_BAD

# Query types
QUERY_TYPE_A = cares.T_A
QUERY_TYPE_AAAA = cares.T_AAAA
QUERY_TYPE_ANY = cares.T_ANY
QUERY_TYPE_CAA = cares.T_CAA
QUERY_TYPE_CNAME = cares.T_CNAME
QUERY_TYPE_MX = cares.T_MX
QUERY_TYPE_NAPTR = cares.T_NAPTR
QUERY_TYPE_NS = cares.T_NS
QUERY_TYPE_PTR = cares.T_PTR
QUERY_TYPE_SOA = cares.T_SOA
QUERY_TYPE_SRV = cares.T_SRV
QUERY_TYPE_TXT = cares.T_TXT

# Query classes
QUERY_CLASS_IN = cares.C_IN
QUERY_CLASS_CHAOS = cares.C_CHAOS
QUERY_CLASS_HS = cares.C_HS
QUERY_CLASS_NONE = cares.C_NONE
QUERY_CLASS_ANY = cares.C_ANY

ARES_VERSION = cares.ares_version(NULL)
PYCARES_ADDRTTL_SIZE = 256


cdef extern from "cares_flag_check.h":
    int pycares_check_qtypes(int qtype) except -1
    int pycares_check_qclasses(int qclass) except -1


cdef extern from "utils.h":
    char* pycares_unicode_str_and_size(str obj, Py_ssize_t* size) except NULL
    int pycares_get_buffer(object obj, Py_buffer *view) except -1
    void pycares_release_buffer(Py_buffer *view)
    
    int pycares_copy_memory(char** ptr_to, object ptr_from) except -1


cdef class AresError(Exception):
    pass

# NOTE: problem with the old _handle_to_channel is 
# that it's not theadsafe, to get around that problem 
# a new implementation was needed.

# Held onto CFFI's bindings as a reference to look at incase I got lost - Vizonex

# extern "Python" void _host_cb(void *arg,
#                               int status,
#                               int timeouts,
#                               struct hostent *hostent);

# extern "Python" void _nameinfo_cb(void *arg,
#                                   int status,
#                                   int timeouts,
#                                   char *node,
#                                   char *service);

# extern "Python" void _query_cb(void *arg,
#                                int status,
#                                int timeouts,
#                                unsigned char *abuf,
#                                int alen);
# extern "Python" void _addrinfo_cb(void *arg,
#                                   int status,
#                                   int timeouts,
#                                   struct ares_addrinfo *res);

cdef void _sock_state_cb(
    void* data, 
    cares.ares_socket_t socket_fd, 
    int readable, 
    int writeable
):
    cdef Channel handle = <Channel>data

   
    pycares_socket_cb(handle, 
        PyLong_FromLong(socket_fd), 
        PyLong_FromLong(readable),
        PyLong_FromLong(writeable)
    )

# # TODO: (Vizonex A New manager to supply for shutdown assistance so that everything is threadsafe)
# cdef void _host_cb(
#     void *arg,
#     int status,
#     int timeouts,
#     cares.hostent *hostent
# ):
#     pass


cdef bint c_ares_threadsafety() noexcept:
    return cares.ares_threadsafety() == cares.ares_bool_t.ARES_TRUE

def ares_threadsafety():
    return PyBool_FromLong(c_ares_threadsafety())



cdef class AresResult:
    __slots__ = ()

    def __repr__(self):
        attrs = ['%s=%s' % (a, getattr(self, a)) for a in self.__slots__]
        return '<%s> %s' % (self.__class__.__name__, ', '.join(attrs))



cdef struct domain_t:
    char** strs
    int size

cdef int domain_append(domain_t* d, object data) except -1:
    if pycares_copy_memory(d.strs[d.size], data) < 0:
        return -1
    d.size += 1
    return 0



cdef inline int domain_init(domain_t* d, object seq) except -1:
    cdef object i
    memset(d, 0, sizeof(domain_t))
    if not PySequence_Check(seq):
        PyErr_SetObject(TypeError, f"Expected a sequence type got: {seq.__class__.__name__}")
        return -1
    
    for i in seq.__iter__():
        if domain_append(d, i) < 0:
            return -1
    return 0

cdef inline domain_free(domain_t* d):
    cdef Py_ssize_t i

    for i in range(i):
        if d.strs[i] != NULL:
            PyMem_Free(d.strs[i])
        

@cython.final
cdef class CallbackHandle:
    # Used to handle and cancel tasks in a threadsafe way
    # Unlike the old cffi technique, this new improved design
    # utilizes reference counting to keep the dns channel alive.
    cdef:
        readonly object channel
        object cb
        bint cancel
    
        # I don't expect a user to hit more than the maximum of 
        # a 64 bit integer, even with all the avalible 
        # ipv6 addresses out there, intergers could always overflow 
        # thus recycling itself over...

        # NOTE: allow python to read if we need to add an asyncio
        # future to it...
        readonly uint64_t id
        object cb_data

    
    def __cinit__(self, object channel, object cb, uint64_t id, cb_data):
        self.channel = channel
        self.cb = cb
        # Used for cancelling the handles...
        self.cancel = False
        self.id = id
        # can be used by the end user, something such as a Future could be used with it...
        self.cb_data = cb_data

    # Cancels task-handle
    cdef void cancel_task(self):
        self.cancel = True

    



cdef class Channel:
    cdef: 
        cares.ares_channel* _channel
        cares.ares_options* options
        object _sock_state_cb_handle
        domain_t domains
        bytes resolvconf_path
        list servers

        # old version used a global variable which is not thread-safe
        # putting all callbacks locally is a better move...

        dict handles # hypothetically: Dict[uint64_t, CallbackHandle]
        uint64_t handle_id
        bint close_issued
    
    def __init__(
        self,
        object flags = None,
        object timeout = None,
        object tries = None,
        object ndots = None,
        object tcp_port = None,
        object udp_port = None,
        list servers = None,
        object domains = None,
        object lookups = None,
        object sock_state_cb = None,
        object socket_send_buffer_size = None,
        object socket_receive_buffer_size = None,
        bint rotate = False,
        object local_ip = None,
        object local_dev = None,
        object resolvconf_path = None,
        bint event_thread = False
    ) -> None:
        
        cdef int optmask = 0
        cdef cares.ares_options options = self.options
        self.resolvconf_path = NULL
        self._channel = NULL
        # create local threadsafe handles...
        self.handles = dict()
        self.handle_id = 0

        if flags is not None:
            options.flags = flags
            optmask |= cares.ARES_OPT_FLAGS
        
        if timeout is not None:
            # rounding needs to be percise hence not using math.round...
            options.timeout = <int>(round((<float>timeout) * 1000))
            optmask |= cares.ARES_OPT_TIMEOUTMS

        if tries is not None:
            options.tries = <int>tries
            optmask |= cares.ARES_OPT_TRIES
        
        if ndots is not None:
            options.ndots = ndots
            optmask |= cares.ARES_OPT_NDOTS

        if tcp_port is not None:
            options.tcp_port = tcp_port
            optmask |= cares.ARES_OPT_TCP_PORT

        if udp_port is not None:
            options.udp_port = udp_port
            optmask |=  cares.ARES_OPT_UDP_PORT

        if socket_send_buffer_size is not None:
            options.socket_send_buffer_size = socket_send_buffer_size
            optmask |=  cares.ARES_OPT_SOCK_SNDBUF

        if socket_receive_buffer_size is not None:
            options.socket_receive_buffer_size = socket_receive_buffer_size
            optmask |=  cares.ARES_OPT_SOCK_RCVBUF

        if sock_state_cb:
            if not callable(sock_state_cb):
                raise TypeError("sock_state_cb is not callable")
            if event_thread:
                raise RuntimeError("sock_state_cb and event_thread cannot be used together")

            # This must be kept alive while the channel is alive.
            self._sock_state_cb_handle = sock_state_cb

            options.sock_state_cb = _sock_state_cb
            optmask |=  cares.ARES_OPT_SOCK_STATE_CB

        if event_thread:
            if not c_ares_threadsafety():
                raise RuntimeError("c-ares is not built with thread safety")
            if sock_state_cb:
                raise RuntimeError("sock_state_cb and event_thread cannot be used together")
            optmask |=  cares.ARES_OPT_EVENT_THREAD
            options.evsys = cares.ARES_EVSYS_DEFAULT

        if lookups:
            options.lookups = lookups
            optmask |=  cares.ARES_OPT_LOOKUPS

        if domains:
            # NOTE: Cython will take care of exception checks for us...
            domain_init(&self.domains, domains)
            options.domains = self.domains.strs
            options.ndomains = self.domains.size
            optmask |= cares.ARES_OPT_DOMAINS

        if rotate:
            optmask |=  cares.ARES_OPT_ROTATE

        if resolvconf_path is not None:
            optmask |=  cares.ARES_OPT_RESOLVCONF
            if PyUnicode_Check(resolvconf_path):
                self.resolvconf_path = bytes(resolvconf_path, "utf-8", "surrogateescape")
            else:
                self.resolvconf_path = bytes(resolvconf_path)
            options.resolvconf_path = PyBytes_AsString(self.resolvconf_path) 
        
        r = cares.ares_init_options(&self._channel, options, optmask)
        if r != cares.ARES_SUCCESS:
            raise AresError('Failed to initialize c-ares channel')
        
        # Initialize all attributes for consistency
        self._event_thread = event_thread
        if servers:
            self.servers = servers

        if local_ip:
            self.set_local_ip(local_ip)

        if local_dev:
            self.set_local_dev(local_dev)


    @property
    def servers(self):
        cdef cares.ares_addr_node *server
        cdef list server_list
        cdef int r = cares.ares_get_servers(self._channel, &server)
        cdef bytes ip
        if r != cares.ARES_SUCCESS:
            raise AresError(r, pycares_strerror(r).decode('utf-8', 'surrogateescape'))

        while server != NULL:
            ip = PyBytes_FromStringAndSize(NULL, cares.INET6_ADDRSTRLEN)
            if cares.ares_inet_ntop(server.family, <void*>server.addr, PyBytes_AS_STRING(ip), cares.INET6_ADDRSTRLEN) != NULL:
                server_list.append(ip)
            server = server.next
        return server_list

 
    cdef int _set_servers(self, object servers) except -1:
        cdef cares.ares_addr_node* c = <cares.ares_addr_node*>PyMem_Calloc(len(servers), sizeof(cares.ares_addr_node))
        cdef Py_ssize_t i
        cdef object server
        cdef Py_buffer view
        cdef int r
        if c == NULL:
            PyErr_NoMemory()
            return -1

        for i, server in enumerate(servers):
            if pycares_get_buffer(server, &view) < 0:
                if c != NULL:
                    PyMem_Free(c)
                return -1

            if cares.ares_inet_pton(AF_INET, view.buf, &c[i].addr.addr4):
                c[i].family = AF_INET
            
            elif cares.ares_inet_pton(AF_INET6, view.buf, &c[i].addr.addr6):
                c[i].family = AF_INET6
            
            pycares_release_buffer(&view)

            if i > 0:
                c[i - 1].next = &c[i]
        
        r = cares.ares_set_servers(self._channel[0], c)
        if r != cares.ARES_SUCCESS:
            PyErr_SetObject(AresError, (r, pycares_strerror(r).decode("utf-8", "surrogateescape")))
            return -1
    
    @servers.setter
    def servers(self, object servers):
        self._set_servers(servers)

    def getsock(self):
        cdef list rfds = []
        cdef list wfds = []
        cdef int bitmask
        cdef int i
        cdef cares.ares_socket_t* socks = <cares.ares_addr_node*>PyMem_Calloc(sizeof(cares.ares_socket_t), cares.ARES_GETSOCK_MAXNUM)
        
        if socks == NULL:
            raise MemoryError
        bitmask = cares.ares_getsock(self._channel[0], socks, cares.ARES_GETSOCK_MAXNUM)
        for i in range(cares.ARES_GETSOCK_MAXNUM):
            if cares.ARES_GETSOCK_READABLE(bitmask, i):
                rfds.append(socks[i])
            if cares.ARES_GETSOCK_WRITABLE(bitmask, i):
                wfds.append(socks[i])

        PyMem_Free(socks)
        return rfds, wfds

    cpdef void process_fd(self, int read_fd, int write_fd):
        cares.ares_process_fd(self._channel[0], <cares.ares_socket_t>read_fd,  <cares.ares_socket_t>write_fd)

    def timeout(self, *args):
        cdef cares.timeval maxtv, tv
        cdef double d
        if PyTuple_GET_ITEM(args, 0) != NULL:
            d = PyLong_AsDouble(<object>PyTuple_GET_ITEM(args, 0))
            if d >= 0.0:
                maxtv.tv_sec = <int>math.floor(d)
                maxtv.tv_usec = int(math.fmod(d, 1.0) * 1000000)
            else:
                raise ValueError("timeout needs to be a positive number or None")
        
        # NOTE: ares_timeout returns tv 
        # so just check if this function is NULL
        if cares.ares_timeout(self._channel[0], &maxtv, &tv) == NULL:
            return 0.0
        return (tv.tv_sec + tv.tv_usec / 1000000.0)

    cdef CallbackHandle _create_callback_handle(self, object cb):
        # special case where python behavior is expected due to format
        # we called it cdef so that it's away from python and remains 
        # private

        cdef CallbackHandle handle

        # moved callback check to right here to play it safe...
        assert callable(cb), f"callback {cb!r} is not callable"
        
        if self._channel is NULL:
            raise RuntimeError("Channel is destroyed, no new queries allowed")
        handle = CallbackHandle(self, cb)
        
        self.handles[self.handle_id] = handle
        self.handle_id += 1

        return handle
    
    # TODO: Maybe add a af:int parameter if user already knows what kind of IP Address to use?
    def gethostbyaddr(self, object addr, object callback, object cb_data = None):
        cdef cares.in_addr addr4
        cdef cares.in6_addr addr6
        cdef Py_buffer view
        cdef CallbackHandle handle
        
        handle = self._create_callback_handle(callback)
        
        # NOTE: cython will handle raising if buffer is not obtained...
        
        pycares_get_buffer(addr, &view)

        # NOTE: ares_gethost.c for lines 74 & 75, 
        # these lengths must line up:
        #   - IPV4 = 4 
        #   - IPV6 = 16

        if cares.ares_inet_pton(AF_INET, <char*>addr.buf, &addr4):
            cares.ares_gethostbyaddr(self._channel[0], &addr4, 4, AF_INET, _host_cb, <void*>handle) 

        elif cares.ares_inet_pton(AF_INET6, <char*>addr.buf, &addr6):
            cares.ares_gethostbyaddr(self._channel[0], &addr6, 16, AF_INET6, _host_cb, <void*>handle)
        
        pycares_release_buffer(&view)
        
        # Return handle for use to utilizes 
        # wrapper like aiodns could utilize it



    # TODO: maybe we could split this into two functions if users know if were using IPV6 or IPV4?
    cpdef int set_local_ip(self, object ip) except -1:
        cdef cares.in_addr addr4
        cdef cares.in6_addr addr6

        cdef Py_buffer view
        pycares_get_buffer(ip, &view)

        if cares.ares_inet_pton(socket.AF_INET, <char*>view.buf, &addr4) == 1:
            cares.ares_set_local_ip4(self._channel[0], socket.ntohl(addr4.s_addr))
            pycares_release_buffer(&view)
            return 0
        elif cares.ares_inet_pton(socket.AF_INET6, <char*>view.buf, &addr6) == 1:
            cares.ares_set_local_ip6(self._channel[0], addr6)
            pycares_release_buffer(&view)
            return 0
        else:
            PyErr_SetObject(ValueError, "invalid IP address")
            return -1

    

cdef class ares_host_result(AresResult):
    cdef: 
        str name
        list aliases
        list addresses
    
    def __init__(self, name, aliases, addresses) -> None:
        super().__init__()
        self.name = name
        self.aliases = aliases
        self.addresses = addresses

    @staticmethod
    cdef ares_host_result from_ptr(cares.hostent* hostent):
        cdef ares_host_result result = ares_host_result.__new__(ares_host_result)
        cdef Py_ssize_t i = 0
        cdef bytes buf
        result.aliases = []
        result.addresses = []
        result.name = PyBytes_FromString(hostent.h_name).decode("utf-8", "surrogateescape")

        while hostent.h_aliases[i] != NULL: 
            result.aliases.append(PyBytes_FromString(hostent.h_aliases[i]))
            i += 1
    
        i = 0
        while hostent.h_addr_list[i] != NULL:
            buf = PyBytes_FromStringAndSize(NULL, cares.INET6_ADDRSTRLEN)
            if cares.ares_inet_ntop(hostent.h_addrtype, hostent.h_addr_list[i], PyBytes_AS_STRING(buf), cares.INET6_ADDRSTRLEN) != NULL:
                result.addresses.append(buf)
            i += 1
        
        return result


cdef void _host_cb(void *arg, int status, int timeouts, cares.hostent *hostent):
    cdef CallbackHandle handle = <CallbackHandle>arg
    # Channel could also be a subclass but this shouldn't be a problem...
    cdef Channel channel = <Channel>handle.channel
    cdef object result
    if handle.cancel:
        del channel.handles[handle.id]
    else:
        callback = handle.cb

        # if were using asyncio for example:
        #   A subclass carrying an eventloop could be utilized 
        #   to grab a future
        
        # NOTE: status originally returned None, 
        # thought it might be smarter to hold onto it 
        # for later reading if nessesary by the developer.
        if status != cares.ARES_SUCCESS:
            result = None
        else:
            result = ares_host_result.from_ptr(hostent)
        

        callback(channel, status, result, handle.id, handle.cb_data)



