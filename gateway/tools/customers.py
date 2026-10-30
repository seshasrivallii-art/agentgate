import psycopg


def get_metadata(conn: psycopg.Connection, customer_id: str) -> dict | None:
    """Trusted ownership and classification, from the database (never from the model)."""
    return conn.execute(
        "SELECT id, tenant_id, classification FROM customers WHERE id = %s",
        (customer_id,),
    ).fetchone()


def support_projection(conn: psycopg.Connection, customer_id: str) -> dict | None:
    """The fixed, support-safe field set. No model-selected columns."""
    return conn.execute(
        """
        SELECT id AS customer_id, display_name, support_plan, open_ticket_count
        FROM customers WHERE id = %s
        """,
        (customer_id,),
    ).fetchone()
