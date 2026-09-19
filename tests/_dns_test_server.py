"""A real, minimal in-process DNS server — shared by
tests/test_api_domain_verification_live.py (direct unit tests of
`verify_dns_txt`) and tests/test_api_domain_verification_endpoints.py
(full HTTP-API end-to-end tests). Not `conftest.py`: pytest loads that
through its own plugin mechanism, which does not reliably support a
plain `import conftest` from a sibling module — same reason
tests/_httpx_verification.py is its own file (see that module's
docstring for the fuller explanation).

Thread-based (`socketserver.UDPServer.serve_forever` on a background
thread), deliberately NOT `asyncio.DatagramProtocol` — the same pattern
this project's HTTP confinement tests already use
(tests/test_httpx_confinement_live.py's `_serve()`), and for the same
reason: `fastapi.testclient.TestClient` runs the app on ITS OWN event
loop, in a separate thread, and a synchronous `client.post(...)` call
blocks the calling thread (and therefore starves whatever asyncio loop
that thread owns) until the response comes back. A DNS test server tied
to an asyncio loop on the SAME thread that calls `client.post(...)`
would never get to run its own `datagram_received` callback while that
call is blocking — confirmed the hard way: real queries timed out
against a server that had the exact right record configured, purely
because nothing was left running the loop to dispatch the reply. A
genuinely separate OS thread, with its own blocking `recvfrom` loop, has
no such dependency on any particular asyncio loop being "live."

Parses real wire-format DNS queries and returns real wire-format TXT
responses via dnspython's own message classes — a real second process's
worth of protocol on the loopback interface, not a mock of the resolver.
"""

from __future__ import annotations

import socketserver
import threading

import dns.asyncresolver
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset


class _DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        server: DNSTestServer = self.server  # type: ignore[assignment]
        try:
            query = dns.message.from_wire(data)
            response = dns.message.make_response(query)
            question = query.question[0]
            qname = question.name.to_text().rstrip(".").lower()
            if question.rdtype == dns.rdatatype.TXT and qname in server.txt_records:
                rdata = dns.rdtypes.ANY.TXT.TXT(
                    dns.rdataclass.IN,
                    dns.rdatatype.TXT,
                    [server.txt_records[qname].encode("utf-8")],
                )
                response.answer.append(dns.rrset.from_rdata(question.name, 60, rdata))
            sock.sendto(response.to_wire(), self.client_address)
        except Exception:  # noqa: S110 - defensive, malformed test input only
            pass


class DNSTestServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, txt_records: dict[str, str] | None = None) -> None:
        super().__init__(("127.0.0.1", 0), _DNSUDPHandler)
        self.txt_records: dict[str, str] = txt_records or {}

    @property
    def port(self) -> int:
        return self.server_address[1]


def start_dns_test_server(
    txt_records: dict[str, str] | None = None,
) -> tuple[DNSTestServer, threading.Thread]:
    server = DNSTestServer(txt_records)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_dns_test_server(server: DNSTestServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def resolver_for(port: int) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = port
    return resolver
