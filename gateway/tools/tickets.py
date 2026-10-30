import uuid

import psycopg

from ..schemas import TicketCreateArgs


def insert_ticket(
    conn: psycopg.Connection, *, tenant_id: str, request_id: uuid.UUID, args: TicketCreateArgs
) -> uuid.UUID | None:
    """Idempotent: tickets.request_id is UNIQUE, so a replay inserts nothing."""
    row = conn.execute(
        """
        INSERT INTO tickets (tenant_id, customer_id, title, description, priority, request_id)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (request_id) DO NOTHING
        RETURNING id
        """,
        (tenant_id, args.customer_id, args.title, args.description, args.priority, request_id),
    ).fetchone()
    return row["id"] if row else None


def find_by_request(conn: psycopg.Connection, request_id: uuid.UUID) -> uuid.UUID | None:
    row = conn.execute("SELECT id FROM tickets WHERE request_id = %s", (request_id,)).fetchone()
    return row["id"] if row else None
