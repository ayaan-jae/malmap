"""
SQLite Database Layer
Handles IOC storage, deduplication, and retrieval
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd

DB_PATH = 'iocs.db'

# SQL for table creation
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    value           TEXT UNIQUE NOT NULL,
    type            TEXT NOT NULL,
    source          TEXT NOT NULL,
    tags            TEXT,
    mitre_id        TEXT,
    mitre_name      TEXT,
    risk_score      INTEGER DEFAULT 50,
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# Create indices for faster queries
CREATE_INDICES_SQL = """
CREATE INDEX IF NOT EXISTS idx_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_source ON iocs(source);
CREATE INDEX IF NOT EXISTS idx_mitre ON iocs(mitre_id);
CREATE INDEX IF NOT EXISTS idx_risk ON iocs(risk_score);
CREATE INDEX IF NOT EXISTS idx_last_seen ON iocs(last_seen DESC);
"""


def init_database():
    """Initialize database and create tables if needed."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode for better concurrency
        cursor = conn.cursor()
        
        cursor.execute(CREATE_TABLE_SQL)
        
        # Create indices
        for sql in CREATE_INDICES_SQL.split(';'):
            if sql.strip():
                cursor.execute(sql)
        
        conn.commit()
        conn.close()
        print(f"✅ Database initialized: {DB_PATH}")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        raise


def upsert_ioc(ioc: Dict) -> bool:
    """
    Insert or update an IOC.
    
    If IOC value already exists (UNIQUE constraint), updates last_seen.
    Otherwise inserts new record.
    
    Args:
        ioc: IOC dict with keys: value, type, source, tags, mitre_id, mitre_name, risk_score
    
    Returns:
        True if successful, False otherwise
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Convert tags list to comma-separated string
        tags_str = ','.join(ioc.get('tags', []))
        
        # Try insert first (will fail if value already exists due to UNIQUE)
        try:
            cursor.execute("""
                INSERT INTO iocs 
                (value, type, source, tags, mitre_id, mitre_name, risk_score, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc['value'],
                ioc['type'],
                ioc['source'],
                tags_str,
                ioc.get('mitre_id', 'Unknown'),
                ioc.get('mitre_name', 'Unclassified'),
                ioc.get('risk_score', 50),
                datetime.now(),
                datetime.now()
            ))
        except sqlite3.IntegrityError:
            # Value already exists, update last_seen and potentially other fields
            cursor.execute("""
                UPDATE iocs
                SET last_seen = ?,
                    risk_score = CASE WHEN ? > risk_score THEN ? ELSE risk_score END
                WHERE value = ?
            """, (
                datetime.now(),
                ioc.get('risk_score', 50),
                ioc.get('risk_score', 50),
                ioc['value']
            ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Database upsert error: {e}")
        return False


def upsert_iocs_batch(iocs: List[Dict]) -> int:
    """
    Batch insert/update multiple IOCs.
    
    Args:
        iocs: List of IOC dicts
    
    Returns:
        Number of IOCs processed
    """
    count = 0
    for ioc in iocs:
        if upsert_ioc(ioc):
            count += 1
    return count


def get_all_iocs() -> pd.DataFrame:
    """
    Retrieve all IOCs from database.
    
    Returns:
        Pandas DataFrame with all IOCs
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM iocs ORDER BY last_seen DESC",
            conn
        )
        conn.close()
        
        # Convert tags string back to list
        if not df.empty and 'tags' in df.columns:
            df['tags'] = df['tags'].apply(lambda x: x.split(',') if x else [])
        
        return df
    except Exception as e:
        print(f"❌ Error retrieving IOCs: {e}")
        return pd.DataFrame()


def get_iocs_by_type(ioc_type: str) -> pd.DataFrame:
    """
    Get all IOCs of a specific type.
    
    Args:
        ioc_type: Type to filter (ip, domain, hash, url)
    
    Returns:
        Pandas DataFrame
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM iocs WHERE type = ? ORDER BY last_seen DESC",
            conn,
            params=(ioc_type,)
        )
        conn.close()
        return df
    except Exception as e:
        print(f"❌ Error retrieving IOCs by type: {e}")
        return pd.DataFrame()


def get_stats() -> Dict:
    """
    Get statistics about IOCs in database.
    
    Returns:
        Dict with keys: total, by_type (dict), by_source (dict), last_updated
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Total count
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total = cursor.fetchone()[0]
        
        # Count by type
        cursor.execute("""
            SELECT type, COUNT(*) as count 
            FROM iocs 
            GROUP BY type
        """)
        by_type = dict(cursor.fetchall())
        
        # Count by source
        cursor.execute("""
            SELECT source, COUNT(*) as count 
            FROM iocs 
            GROUP BY source
        """)
        by_source = dict(cursor.fetchall())
        
        # Last updated
        cursor.execute("SELECT MAX(last_seen) FROM iocs")
        last_updated = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total': total,
            'by_type': by_type,
            'by_source': by_source,
            'last_updated': last_updated
        }
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return {
            'total': 0,
            'by_type': {},
            'by_source': {},
            'last_updated': None
        }


def clear_old_iocs(days: int = 30) -> int:
    """
    Delete IOCs not seen in the last N days.
    
    Args:
        days: Number of days to keep
    
    Returns:
        Number of deleted IOCs
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM iocs 
            WHERE datetime(last_seen) <= datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted > 0:
            print(f"🗑️  Deleted {deleted} IOCs not seen in {days} days")
        
        return deleted
    except Exception as e:
        print(f"❌ Error deleting old IOCs: {e}")
        return 0


def search_iocs(query: str, field: str = 'value') -> pd.DataFrame:
    """
    Search IOCs by a specific field.
    
    Args:
        query: Search query (case-insensitive)
        field: Field to search in (value, type, source, mitre_id, etc.)
    
    Returns:
        Pandas DataFrame of matching IOCs
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        # Use LIKE for case-insensitive search
        df = pd.read_sql_query(
            f"SELECT * FROM iocs WHERE {field} LIKE ? ORDER BY last_seen DESC",
            conn,
            params=(f'%{query}%',)
        )
        conn.close()
        return df
    except Exception as e:
        print(f"❌ Error searching IOCs: {e}")
        return pd.DataFrame()


if __name__ == '__main__':
    # Test database
    print("Testing Database:")
    print("-" * 60)
    
    init_database()
    
    test_iocs = [
        {
            'value': '192.168.1.1',
            'type': 'ip',
            'source': 'test',
            'tags': ['test', 'malware'],
            'mitre_id': 'T1071',
            'mitre_name': 'Application Layer Protocol',
            'risk_score': 75
        },
        {
            'value': 'malware.com',
            'type': 'domain',
            'source': 'test',
            'tags': ['c2'],
            'mitre_id': 'T1071',
            'mitre_name': 'Application Layer Protocol',
            'risk_score': 85
        }
    ]
    
    print("Inserting test IOCs...")
    for ioc in test_iocs:
        upsert_ioc(ioc)
    
    print("\nRetrieving all IOCs...")
    df = get_all_iocs()
    print(df)
    
    print("\nGetting stats...")
    stats = get_stats()
    print(f"Total IOCs: {stats['total']}")
    print(f"By type: {stats['by_type']}")
    print(f"By source: {stats['by_source']}")
