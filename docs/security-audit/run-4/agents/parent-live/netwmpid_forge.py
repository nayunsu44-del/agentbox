"""Map a 1x1 titled window whose _NET_WM_PID names another pid (uid 1001, python3 + libX11 via ctypes).

usage (inside the desktop container): python3 netwmpid_forge.py <pid-to-claim> [seconds]
"""
import ctypes, sys, time
pid, secs = int(sys.argv[1]), float(sys.argv[2] if len(sys.argv) > 2 else 600)
X = ctypes.cdll.LoadLibrary("libX11.so.6")
X.XOpenDisplay.restype = ctypes.c_void_p
X.XDefaultRootWindow.argtypes = [ctypes.c_void_p]; X.XDefaultRootWindow.restype = ctypes.c_ulong
X.XCreateSimpleWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong] + [ctypes.c_int] * 2 + [ctypes.c_uint] * 3 + [ctypes.c_ulong] * 2
X.XCreateSimpleWindow.restype = ctypes.c_ulong
X.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]; X.XInternAtom.restype = ctypes.c_ulong
X.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
X.XStoreName.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_char_p]
X.XMapWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
X.XFlush.argtypes = [ctypes.c_void_p]
d = X.XOpenDisplay(None)
assert d, "no display"
w = X.XCreateSimpleWindow(d, X.XDefaultRootWindow(d), 0, 0, 1, 1, 0, 0, 0)
v = ctypes.c_ulong(pid)
X.XChangeProperty(d, w, X.XInternAtom(d, b"_NET_WM_PID", 0), X.XInternAtom(d, b"CARDINAL", 0), 32, 0, ctypes.byref(v), 1)
X.XStoreName(d, w, b"x")
X.XMapWindow(d, w)
X.XFlush(d)
print("window", w, "claims pid", pid, flush=True)
time.sleep(secs)
