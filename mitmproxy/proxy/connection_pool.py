"""
Global connection pool for upstream server connections.

Allows reuse of idle server connections across different client handlers,
avoiding the overhead of repeated TCP handshakes and TLS negotiations.

The pool is keyed by (address, tls, via, transport_protocol) and stores
idle connections with their associated asyncio readers/writers. Connections
are evicted after a configurable idle timeout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field

from mitmproxy.connection import Address
from mitmproxy.connection import Connection
from mitmproxy.connection import ConnectionState
from mitmproxy.connection import Server
from mitmproxy.connection import TransportProtocol
from mitmproxy.net import server_spec

import mitmproxy_rs

logger = logging.getLogger(__name__)


PoolKey = tuple[Address, bool, server_spec.ServerSpec | None, TransportProtocol]


def _pool_key(conn: Server) -> PoolKey:
    assert conn.address is not None
    return (conn.address, conn.tls, conn.via, conn.transport_protocol)


@dataclass
class PooledConnection:
    """An idle server connection held by the pool."""

    connection: Server
    reader: asyncio.StreamReader | mitmproxy_rs.Stream
    writer: asyncio.StreamWriter | mitmproxy_rs.Stream
    timestamp_returned: float = field(default_factory=time.time)


class ConnectionPool:
    """
    Global pool of idle upstream server connections.

    Connections are returned here when an HTTP transaction completes with keep-alive semantics.
    A subsequent request to the same (address, tls, via, transport_protocol) can reuse
    an existing connection instead of opening a new one.
    """

    _pool: defaultdict[PoolKey, list[PooledConnection]]
    _idle_timeout: float
    _max_per_key: int
    _gc_task: asyncio.Task | None
    _closed: bool

    def __init__(
        self,
        idle_timeout: float = 30.0,
        max_per_key: int = 5,
    ) -> None:
        self._pool = defaultdict(list)
        self._idle_timeout = idle_timeout
        self._max_per_key = max_per_key
        self._gc_task = None
        self._closed = False

    def start(self) -> None:
        if self._gc_task is None and not self._closed:
            self._gc_task = asyncio.ensure_future(self._gc_loop())

    async def close(self) -> None:
        self._closed = True
        if self._gc_task is not None:
            self._gc_task.cancel()
            try:
                await self._gc_task
            except asyncio.CancelledError:
                pass
            self._gc_task = None
        for entries in self._pool.values():
            for entry in entries:
                self._close_writer(entry)
        self._pool.clear()

    def put(
        self,
        connection: Server,
        reader: asyncio.StreamReader | mitmproxy_rs.Stream,
        writer: asyncio.StreamWriter | mitmproxy_rs.Stream,
    ) -> bool:
        """
        Return an idle connection to the pool.

        Returns True if the connection was accepted, False if it was rejected
        (pool full, connection not healthy, etc).
        """
        if self._closed:
            return False
        if not connection.connected:
            return False
        if connection.address is None:
            return False

        key = _pool_key(connection)
        entries = self._pool[key]

        if len(entries) >= self._max_per_key:
            return False

        if isinstance(writer, asyncio.StreamWriter) and writer.is_closing():
            return False

        entries.append(PooledConnection(connection, reader, writer))
        logger.debug(
            f"Connection to {connection.address} returned to pool "
            f"(pool size for key: {len(entries)})"
        )
        return True

    def get(
        self,
        address: Address,
        tls: bool,
        via: server_spec.ServerSpec | None,
        transport_protocol: TransportProtocol,
    ) -> PooledConnection | None:
        """
        Acquire an idle connection from the pool, or None if none available.

        The returned connection is removed from the pool.
        """
        if self._closed:
            return None

        key = (address, tls, via, transport_protocol)
        entries = self._pool.get(key)
        if not entries:
            return None

        now = time.time()
        while entries:
            entry = entries.pop(0)
            age = now - entry.timestamp_returned
            if age > self._idle_timeout:
                self._close_writer(entry)
                continue
            if not entry.connection.connected:
                self._close_writer(entry)
                continue
            if isinstance(entry.writer, asyncio.StreamWriter) and entry.writer.is_closing():
                continue

            logger.debug(
                f"Reusing pooled connection to {address} "
                f"(idle {age:.1f}s, remaining in pool: {len(entries)})"
            )
            if not entries:
                del self._pool[key]
            return entry

        del self._pool[key]
        return None

    @property
    def pool_size(self) -> int:
        return sum(len(v) for v in self._pool.values())

    async def _gc_loop(self) -> None:
        """Periodically evict expired connections."""
        try:
            while not self._closed:
                await asyncio.sleep(self._idle_timeout / 2)
                self._evict_expired()
        except asyncio.CancelledError:
            return

    def _evict_expired(self) -> None:
        now = time.time()
        empty_keys = []
        for key, entries in self._pool.items():
            entries[:] = [
                e for e in entries
                if now - e.timestamp_returned <= self._idle_timeout and e.connection.connected
                or not self._close_writer(e)
            ]
            if not entries:
                empty_keys.append(key)
        for key in empty_keys:
            del self._pool[key]

    @staticmethod
    def _close_writer(entry: PooledConnection) -> bool:
        """Close a pooled connection's writer. Always returns True (for use in comprehensions)."""
        try:
            if isinstance(entry.writer, asyncio.StreamWriter):
                if not entry.writer.is_closing():
                    entry.writer.close()
            else:
                entry.writer.close()
        except OSError:
            pass
        entry.connection.state = ConnectionState.CLOSED
        return True
