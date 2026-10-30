from typing import Sequence

import psycopg


def search(
    conn: psycopg.Connection,
    *,
    tenant_id: str,
    classifications: Sequence[str],
    query: str,
    limit: int,
) -> list[dict]:
    """Authorization filters are applied inside the query, before rows leave the database."""
    if not classifications:
        return []
    return conn.execute(
        """
        SELECT id, tenant_id, classification, title, left(body, 1500) AS excerpt
        FROM documents
        WHERE tenant_id = %(tenant)s
          AND classification = ANY(%(classes)s)
          AND search @@ websearch_to_tsquery('english', %(q)s)
        ORDER BY ts_rank(search, websearch_to_tsquery('english', %(q)s)) DESC, id
        LIMIT %(limit)s
        """,
        {"tenant": tenant_id, "classes": list(classifications), "q": query, "limit": limit},
    ).fetchall()
