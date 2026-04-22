from mitmproxy import http
from mitmproxy.coretypes import multidict

req = http.Request.make(
    "GET", "http://example.com",
    headers=[
        (b"cookie", b"_rdt_uuid=123; foo=bar"),
        (b"cookie", b"_gcl_au=456")
    ]
)
print("Before:", req.headers.get_all("cookie"))
print("Cookies property type:", type(req.cookies))
print("Cookies items:", list(req.cookies.items(multi=True)))

del req.cookies["foo"]
print("After removing 'foo':", req.headers.get_all("cookie"))

