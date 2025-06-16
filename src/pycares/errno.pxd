

cdef extern from "pycares_err_lookup.h":
    bytes pycares_err_name(int status)
    bytes pycares_strerror(int code)
