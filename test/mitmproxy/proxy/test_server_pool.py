import asyncio
import collections
from typing import Callable
from unittest import mock

import pytest

from mitmproxy import options
from mitmproxy.connection import Client
from mitmproxy.connection import ConnectionState
from mitmproxy.connection import Server
from mitmproxy.proxy import commands
from mitmproxy.proxy import server
from mitmproxy.proxy import server_hooks
from mitmproxy.proxy.connection_pool import ConnectionPool
from mitmproxy.proxy.mode_specs import ProxyMode


class MockConnectionHandler(server.SimpleConnectionHandler):
    hook_handlers: dict[str, mock.Mock | Callable]

    def __init__(self, pool=None):
        super().__init__(
            reader=mock.Mock(),
            writer=mock.Mock(),
            options=options.Options(),
            mode=ProxyMode.parse("regular"),
            hook_handlers=collections.defaultdict(lambda: mock.Mock()),
            pool=pool,
        )


def _pre_populate_hooks(handler):
    """Access hooks to pre-populate the defaultdict, matching existing test patterns."""
    _ = handler.hook_handlers["server_connect"]
    _ = handler.hook_handlers["server_connected"]
    _ = handler.hook_handlers["server_connect_error"]
    _ = handler.hook_handlers["server_disconnected"]


@pytest.mark.parametrize("pool_has_connection", [True, False])
async def test_open_connection_with_pool(pool_has_connection, monkeypatch):
    """Test that open_connection checks the pool before opening a new connection."""
    pool = ConnectionPool(idle_timeout=30)

    if pool_has_connection:
        pooled_server = Server(address=("server", 1234))
        pooled_server.state = ConnectionState.OPEN
        pooled_server.peername = ("1.2.3.4", 1234)
        pooled_server.sockname = ("192.168.1.1", 54321)
        pooled_server.timestamp_start = 1.0
        pooled_server.timestamp_tcp_setup = 2.0

        pooled_reader = mock.MagicMock(spec=asyncio.StreamReader)
        pooled_writer = mock.MagicMock(spec=asyncio.StreamWriter)
        pooled_writer.is_closing.return_value = False
        pool.put(pooled_server, pooled_reader, pooled_writer)

    handler = MockConnectionHandler(pool=pool)
    _pre_populate_hooks(handler)

    monkeypatch.setattr(
        asyncio,
        "open_connection",
        mock.AsyncMock(return_value=(mock.MagicMock(), mock.MagicMock())),
    )
    monkeypatch.setattr(
        MockConnectionHandler, "handle_connection", mock.AsyncMock()
    )
    monkeypatch.setattr(
        MockConnectionHandler, "server_event", mock.AsyncMock()
    )

    target = Server(address=("server", 1234))
    await handler.open_connection(commands.OpenConnection(connection=target))

    if pool_has_connection:
        assert target.state == ConnectionState.OPEN
        assert target.peername == ("1.2.3.4", 1234)
        assert pool.pool_size == 0
        # server_connect hook should NOT be called for pooled connections.
        handler.hook_handlers["server_connect"].assert_not_called()
    else:
        handler.hook_handlers["server_connect"].assert_called_once()


async def test_open_connection_pool_miss_opens_new(monkeypatch):
    """When the pool has no matching connection, a fresh one is opened normally."""
    pool = ConnectionPool(idle_timeout=30)

    other_server = Server(address=("other", 5678))
    other_server.state = ConnectionState.OPEN
    other_server.peername = ("5.6.7.8", 5678)
    other_server.sockname = ("192.168.1.1", 54322)
    r, w = mock.MagicMock(spec=asyncio.StreamReader), mock.MagicMock(spec=asyncio.StreamWriter)
    w.is_closing.return_value = False
    pool.put(other_server, r, w)

    handler = MockConnectionHandler(pool=pool)
    _pre_populate_hooks(handler)
    monkeypatch.setattr(
        asyncio,
        "open_connection",
        mock.AsyncMock(return_value=(mock.MagicMock(), mock.MagicMock())),
    )
    monkeypatch.setattr(
        MockConnectionHandler, "handle_connection", mock.AsyncMock()
    )
    monkeypatch.setattr(
        MockConnectionHandler, "server_event", mock.AsyncMock()
    )

    target = Server(address=("server", 1234))
    await handler.open_connection(commands.OpenConnection(connection=target))

    assert pool.pool_size == 1
    handler.hook_handlers["server_connect"].assert_called_once()


async def test_can_return_to_pool():
    """Test _can_return_to_pool checks."""
    pool = ConnectionPool()
    handler = MockConnectionHandler(pool=pool)

    server_conn = Server(address=("example.com", 443))
    server_conn.state = ConnectionState.OPEN
    reader = mock.MagicMock(spec=asyncio.StreamReader)
    writer = mock.MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False

    io = server.ConnectionIO(handler=mock.MagicMock(), reader=reader, writer=writer)

    assert handler._can_return_to_pool(server_conn, io) is True

    server_conn.state = ConnectionState.CLOSED
    assert handler._can_return_to_pool(server_conn, io) is False
    server_conn.state = ConnectionState.OPEN

    server_conn.error = "bad cert"
    assert handler._can_return_to_pool(server_conn, io) is False
    server_conn.error = None

    io_no_reader = server.ConnectionIO(handler=mock.MagicMock(), reader=None, writer=writer)
    assert handler._can_return_to_pool(server_conn, io_no_reader) is False

    client_conn = Client(
        peername=("127.0.0.1", 1234),
        sockname=("127.0.0.1", 8080),
        state=ConnectionState.OPEN,
    )
    assert handler._can_return_to_pool(client_conn, io) is False


async def test_return_to_pool():
    """Test _return_to_pool puts connection in the pool."""
    pool = ConnectionPool()
    handler = MockConnectionHandler(pool=pool)

    server_conn = Server(address=("example.com", 443))
    server_conn.state = ConnectionState.OPEN
    server_conn.peername = ("1.2.3.4", 443)
    server_conn.sockname = ("192.168.1.1", 54321)
    reader = mock.MagicMock(spec=asyncio.StreamReader)
    writer = mock.MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False

    io = server.ConnectionIO(handler=mock.MagicMock(), reader=reader, writer=writer)
    handler.transports[server_conn] = io

    handler._return_to_pool(server_conn, io)

    assert pool.pool_size == 1
    assert server_conn not in handler.transports

    result = pool.get(("example.com", 443), False, None, "tcp")
    assert result is not None
    assert result.reader is reader


async def test_no_pool_normal_behavior(monkeypatch):
    """Without a pool, behavior is unchanged."""
    handler = MockConnectionHandler(pool=None)
    _pre_populate_hooks(handler)
    assert handler.pool is None

    monkeypatch.setattr(
        asyncio,
        "open_connection",
        mock.AsyncMock(return_value=(mock.MagicMock(), mock.MagicMock())),
    )
    monkeypatch.setattr(
        MockConnectionHandler, "handle_connection", mock.AsyncMock()
    )
    monkeypatch.setattr(
        MockConnectionHandler, "server_event", mock.AsyncMock()
    )

    target = Server(address=("server", 1234))
    await handler.open_connection(commands.OpenConnection(connection=target))

    handler.hook_handlers["server_connect"].assert_called_once()
