# p11-kit -- Information about our contribution rules and coding style

# Test suite

New functionality should be accompanied by a test case which verifies
the correctness of p11-kit's operation on successful use of the new
functionality, as well as on failure cases.  The p11-kit test suite is
run on "ninja test" if you use meson for building, or on "make check"
if you use autotools.

Bug fixes should also come with a test case that exercises the code
path that previously failed to operate.  This prevents future
regressions.

# Coding style

In general, use [the Linux kernel coding
style](https://www.kernel.org/doc/html/latest/process/coding-style.html),
except that we put a space between function name and open parenthesis.

# API documentation

Use [gtk-doc](https://www.gtk.org/gtk-doc/) for API documentation.

# Library symbol versioning

We use [the libtool versioning scheme](https://www.gnu.org/software/libtool/manual/html_node/Versioning.html#Versioning) to ensure ABI compatibility.  If you add a new API function, update [libp11-kit.map](https://github.com/p11-glue/p11-kit/blob/master/p11-kit/libp11-kit.map) and [libp11-kit-*.dll.def](https://github.com/p11-glue/p11-kit/blob/master/p11-kit/libp11-kit-0.dll.def) accordingly.

# Resources:

* [Documentation on developing p11-kit](https://p11-glue.github.io/p11-glue/p11-kit/manual/devel.html)
* [Code available at](https://github.com/p11-glue/p11-kit)
* [General Website](https://p11-glue.github.io/p11-glue/p11-kit.html)
* [Mailing list](https://lists.freedesktop.org/mailman/listinfo/p11-glue)
* [Report bugs](https://github.com/p11-glue/p11-kit/issues)
