import asyncio
import time
from unittest import mock

import pytest

from mitmproxy.connection import ConnectionState
from mitmproxy.connection import Server
from mitmproxy.proxy.connection_pool import ConnectionPool
from mitmproxy.proxy.connection_pool import PooledConnection
from mitmproxy.proxy.connection_pool import _pool_key


def _make_server(
    address=("example.com", 443),
    tls=True,
    via=None,
    transport_protocol="tcp",
    state=ConnectionState.OPEN,
) -> Server:
    s = Server(address=address, transport_protocol=transport_protocol)
    s.tls = tls
    s.via = via
    s.state = state
    s.peername = ("93.184.216.34", 443)
    s.sockname = ("192.168.1.1", 54321)
    return s


def _make_rw():
    reader = mock.MagicMock(spec=asyncio.StreamReader)
    writer = mock.MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False
    return reader, writer


class TestPoolKey:
    def test_basic(self):
        s = _make_server()
        key = _pool_key(s)
        assert key == (("example.com", 443), True, None, "tcp")

    def test_with_via(self):
        s = _make_server(via=("http", ("proxy.local", 8080)))
        key = _pool_key(s)
        assert key == (("example.com", 443), True, ("http", ("proxy.local", 8080)), "tcp")


class TestConnectionPoolPutGet:
    def test_put_and_get(self):
        pool = ConnectionPool(idle_timeout=30)
        server = _make_server()
        reader, writer = _make_rw()

        assert pool.put(server, reader, writer) is True
        assert pool.pool_size == 1

        result = pool.get(("example.com", 443), True, None, "tcp")
        assert result is not None
        assert result.reader is reader
        assert result.writer is writer
        assert pool.pool_size == 0

    def test_get_empty(self):
        pool = ConnectionPool()
        assert pool.get(("example.com", 443), True, None, "tcp") is None

    def test_get_wrong_key(self):
        pool = ConnectionPool()
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        assert pool.get(("other.com", 443), True, None, "tcp") is None
        assert pool.get(("example.com", 80), True, None, "tcp") is None
        assert pool.get(("example.com", 443), False, None, "tcp") is None

    def test_put_closed_connection_rejected(self):
        pool = ConnectionPool()
        server = _make_server(state=ConnectionState.CLOSED)
        reader, writer = _make_rw()

        assert pool.put(server, reader, writer) is False
        assert pool.pool_size == 0

    def test_put_no_address_rejected(self):
        pool = ConnectionPool()
        server = Server(address=None)
        server.state = ConnectionState.OPEN
        reader, writer = _make_rw()

        assert pool.put(server, reader, writer) is False

    def test_put_closing_writer_rejected(self):
        pool = ConnectionPool()
        server = _make_server()
        reader, writer = _make_rw()
        writer.is_closing.return_value = True

        assert pool.put(server, reader, writer) is False

    def test_max_per_key(self):
        pool = ConnectionPool(max_per_key=2)

        for i in range(2):
            server = _make_server()
            reader, writer = _make_rw()
            assert pool.put(server, reader, writer) is True

        server = _make_server()
        reader, writer = _make_rw()
        assert pool.put(server, reader, writer) is False
        assert pool.pool_size == 2

    def test_fifo_order(self):
        pool = ConnectionPool(max_per_key=3)
        readers = []

        for i in range(3):
            server = _make_server()
            reader, writer = _make_rw()
            readers.append(reader)
            pool.put(server, reader, writer)

        for i in range(3):
            result = pool.get(("example.com", 443), True, None, "tcp")
            assert result is not None
            assert result.reader is readers[i]

    def test_get_skips_expired(self):
        pool = ConnectionPool(idle_timeout=1)
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        pool._pool[_pool_key(server)][0].timestamp_returned = time.time() - 2

        assert pool.get(("example.com", 443), True, None, "tcp") is None
        assert pool.pool_size == 0

    def test_get_skips_disconnected(self):
        pool = ConnectionPool()
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        server.state = ConnectionState.CLOSED

        assert pool.get(("example.com", 443), True, None, "tcp") is None

    def test_get_skips_closing_writer(self):
        pool = ConnectionPool()
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        writer.is_closing.return_value = True

        assert pool.get(("example.com", 443), True, None, "tcp") is None

    def test_multiple_keys(self):
        pool = ConnectionPool()

        s1 = _make_server(address=("one.com", 443))
        r1, w1 = _make_rw()
        pool.put(s1, r1, w1)

        s2 = _make_server(address=("two.com", 443))
        r2, w2 = _make_rw()
        pool.put(s2, r2, w2)

        assert pool.pool_size == 2

        result = pool.get(("two.com", 443), True, None, "tcp")
        assert result is not None
        assert result.reader is r2

        result = pool.get(("one.com", 443), True, None, "tcp")
        assert result is not None
        assert result.reader is r1


class TestConnectionPoolClosed:
    def test_put_on_closed_pool(self):
        pool = ConnectionPool()
        pool._closed = True
        server = _make_server()
        reader, writer = _make_rw()
        assert pool.put(server, reader, writer) is False

    def test_get_on_closed_pool(self):
        pool = ConnectionPool()
        pool._closed = True
        assert pool.get(("example.com", 443), True, None, "tcp") is None

    @pytest.mark.asyncio
    async def test_close_drains_pool(self):
        pool = ConnectionPool()
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        assert pool.pool_size == 1
        await pool.close()
        assert pool.pool_size == 0
        assert pool._closed is True
        writer.close.assert_called_once()


class TestConnectionPoolGC:
    def test_evict_expired(self):
        pool = ConnectionPool(idle_timeout=1)
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        pool._pool[_pool_key(server)][0].timestamp_returned = time.time() - 2

        pool._evict_expired()
        assert pool.pool_size == 0

    def test_evict_keeps_fresh(self):
        pool = ConnectionPool(idle_timeout=30)
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        pool._evict_expired()
        assert pool.pool_size == 1

    def test_evict_disconnected(self):
        pool = ConnectionPool(idle_timeout=30)
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        server.state = ConnectionState.CLOSED

        pool._evict_expired()
        assert pool.pool_size == 0

    @pytest.mark.asyncio
    async def test_gc_loop_runs(self):
        pool = ConnectionPool(idle_timeout=0.1)
        pool.start()
        server = _make_server()
        reader, writer = _make_rw()
        pool.put(server, reader, writer)

        pool._pool[_pool_key(server)][0].timestamp_returned = time.time() - 1

        await asyncio.sleep(0.2)
        assert pool.pool_size == 0
        await pool.close()


class TestPooledConnection:
    def test_timestamp(self):
        server = _make_server()
        reader, writer = _make_rw()
        before = time.time()
        pc = PooledConnection(server, reader, writer)
        after = time.time()
        assert before <= pc.timestamp_returned <= after
