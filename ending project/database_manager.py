import sqlite3
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from contextlib import contextmanager
import hashlib
import os

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    SQLite Database Manager for Parental Control System

    This class handles all database operations including:
    - User management (parents)
    - Children management
    - Blocked domains management
    - Browsing history tracking
    - Security alerts logging

    Replaces all JSON file operations with efficient SQLite database operations.
    """

    def __init__(self, db_path: str = "parental_control.db"):
        """
        Initialize the database manager

        Args:
            db_path (str): Path to the SQLite database file

        Raises:
            Exception: If database initialization fails
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_database()
        logger.info(f"DatabaseManager initialized with: {db_path}")

    def _init_database(self) -> None:
        """
        Initialize the database and create all required tables

        Raises:
            Exception: If database initialization fails
        """
        try:
            with self._get_connection() as conn:
                self._create_tables(conn)
                logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    @contextmanager
    def _get_connection(self):
        """
        Context manager for secure database connections

        Provides automatic transaction management with commit/rollback
        and ensures connections are properly closed.

        Yields:
            sqlite3.Connection: Database connection with row factory
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")  # Enforce foreign key constraints
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def add_security_alert(self, client_ip: str, risk_level: str, alert_type: str, details: dict):
        """Add security alert to database"""
        try:
            with self._lock, self._get_connection() as conn:  # <-- äùúîù ácontext manager
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_alerts (client_ip, risk_level, alert_type, details, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (client_ip, risk_level, alert_type, json.dumps(details), time.time()))

                self.logger.info(f"Security alert saved: {alert_type} from {client_ip}")
                return True
        except Exception as e:
            self.logger.error(f"Error adding security alert: {e}")
            return False

    def get_security_alerts(self, limit: int = 50) -> List[dict]:
        """Get recent security alerts"""
        try:
            with self._get_connection() as conn:  # <-- äùúîù ácontext manager
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT client_ip, risk_level, alert_type, details, timestamp
                    FROM security_alerts
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

                alerts = []
                for row in cursor.fetchall():
                    alerts.append({
                        'client_ip': row[0],
                        'risk_level': row[1],
                        'alert_type': row[2],
                        'details': json.loads(row[3]),
                        'timestamp': row[4]
                    })

                return alerts
        except Exception as e:
            self.logger.error(f"Error getting security alerts: {e}")
            return []


    def _create_tables(self, conn: sqlite3.Connection) -> None:
        """Create all required database tables and indexes"""
        cursor = conn.cursor()

        # Users table (parents)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                fullname TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Children table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS children (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                client_address TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')

        # Blocked domains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                child_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (child_id) REFERENCES children (id) ON DELETE CASCADE,
                UNIQUE(child_id, domain)
            )
        ''')

        # Browsing history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS browsing_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                child_id INTEGER NOT NULL,
                original_domain TEXT,
                main_domain TEXT,
                display_name TEXT,
                was_blocked BOOLEAN DEFAULT 0,
                timestamp TIMESTAMP NOT NULL,
                FOREIGN KEY (child_id) REFERENCES children (id) ON DELETE CASCADE
            )
        ''')

        # Security alerts table - SINGLE VERSION ONLY!
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        ''')

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_browsing_history_child_id ON browsing_history(child_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_browsing_history_timestamp ON browsing_history(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_domains_child_id ON blocked_domains(child_id)")


    def register_user(self, email: str, fullname: str, password: str) -> Tuple[bool, str]:
        """
        Register a new parent user in the system

        Args:
            email (str): User's email address (must be unique)
            fullname (str): User's full name
            password (str): User's password (will be hashed)

        Returns:
            Tuple[bool, str]: (success_status, message)

        Raises:
            None: Returns error message instead of raising exceptions
        """
        # Input validation
        if not email or not fullname or not password:
            return False, "All fields must be filled"

        if len(password) < 6:
            return False, "Password must contain at least 6 characters"

        # Hash password using SHA-256
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (email, fullname, password_hash)
                    VALUES (?, ?, ?)
                ''', (email, fullname, password_hash))

                logger.info(f"User registered: {email}")
                return True, "User registered successfully"

        except sqlite3.IntegrityError:
            return False, "Email address already exists in system"
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return False, "Registration failed"

    def validate_login(self, email: str, password: str) -> bool:
        """
        Validate user login credentials

        Args:
            email (str): User's email address
            password (str): User's password

        Returns:
            bool: True if credentials are valid, False otherwise
        """
        if not email or not password:
            return False

        # Hash the provided password for comparison
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT password_hash FROM users WHERE email = ?
                ''', (email,))

                result = cursor.fetchone()
                return result and result['password_hash'] == password_hash

        except Exception as e:
            logger.error(f"Login validation error: {e}")
            return False

    def get_user_fullname(self, email: str) -> Optional[str]:
        """
        Get the full name of a user by email

        Args:
            email (str): User's email address

        Returns:
            Optional[str]: User's full name or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT fullname FROM users WHERE email = ?', (email,))
                result = cursor.fetchone()
                return result['fullname'] if result else None
        except Exception as e:
            logger.error(f"Error getting user fullname: {e}")
            return None

    # ===============================
    # Children Management Functions (replaces children_data)
    # ===============================

    def add_child(self, child_name: str) -> bool:
        """
        Add a new child to the system

        Args:
            child_name (str): Name of the child to add

        Returns:
            bool: True if child was added successfully, False if already exists
        """
        if not child_name or not child_name.strip():
            return False

        child_name = child_name.strip()

        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO children (name) VALUES (?)
                ''', (child_name,))

                logger.info(f"Child added: {child_name}")
                return True

        except sqlite3.IntegrityError:
            logger.debug(f"Child already exists: {child_name}")
            return False
        except Exception as e:
            logger.error(f"Error adding child: {e}")
            return False

    def remove_child(self, child_name: str) -> bool:
        """
        Remove a child from the system

        This will also cascade delete all associated blocked domains,
        browsing history, and security alerts.

        Args:
            child_name (str): Name of the child to remove

        Returns:
            bool: True if child was removed successfully, False if not found
        """
        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM children WHERE name = ?', (child_name,))

                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Child removed: {child_name}")
                return success

        except Exception as e:
            logger.error(f"Error removing child: {e}")
            return False

    def get_all_children(self) -> Dict[str, Dict]:
        """
        Get all active children in the system

        Returns data in format compatible with existing code that used
        the global children_data dictionary.

        Returns:
            Dict[str, Dict]: Dictionary with child names as keys and info as values
            Format: {
                "child_name": {
                    "blocked_domains": set(),
                    "client_address": str or None,
                    "last_seen": timestamp or None
                }
            }
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, name, client_address, last_seen 
                    FROM children WHERE is_active = 1
                ''')

                children_data = {}
                for row in cursor.fetchall():
                    # Get blocked domains for this child
                    blocked_domains = self.get_child_blocked_domains_set(row['name'])

                    children_data[row['name']] = {
                        'blocked_domains': blocked_domains,
                        'client_address': row['client_address'],
                        'last_seen': row['last_seen']
                    }

                return children_data

        except Exception as e:
            logger.error(f"Error getting children: {e}")
            return {}

    def update_child_connection(self, child_name: str, client_address: Optional[str] = None,
                                last_seen: Optional[float] = None) -> None:
        """
        Update child connection information

        Args:
            child_name (str): Name of the child
            client_address (Optional[str]): Client's IP address or None for disconnect
            last_seen (Optional[float]): Timestamp of last activity or None
        """
        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()

                last_seen_dt = datetime.fromtimestamp(last_seen) if last_seen else datetime.now()

                cursor.execute('''
                    UPDATE children 
                    SET client_address = ?, last_seen = ?
                    WHERE name = ?
                ''', (client_address, last_seen_dt, child_name))

        except Exception as e:
            logger.error(f"Error updating child connection: {e}")

    def child_exists(self, child_name: str) -> bool:
        """
        Check if a child exists in the system

        Args:
            child_name (str): Name of the child to check

        Returns:
            bool: True if child exists and is active, False otherwise
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM children WHERE name = ? AND is_active = 1', (child_name,))
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking child existence: {e}")
            return False

    # ===============================
    # Blocked Domains Management Functions
    # ===============================

    def add_blocked_domain(self, child_name: str, domain: str) -> bool:
        """
        Add a blocked domain for a specific child

        Args:
            child_name (str): Name of the child
            domain (str): Domain to block (will be normalized to lowercase)

        Returns:
            bool: True if domain was added successfully, False if already exists
        """
        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR IGNORE INTO blocked_domains (child_id, domain)
                    SELECT id, ? FROM children WHERE name = ?
                ''', (domain.lower().strip(), child_name))

                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Added blocked domain {domain} for {child_name}")
                return success

        except Exception as e:
            logger.error(f"Error adding blocked domain: {e}")
            return False

    def remove_blocked_domain(self, child_name: str, domain: str) -> bool:
        """
        Remove a blocked domain for a specific child

        Args:
            child_name (str): Name of the child
            domain (str): Domain to unblock

        Returns:
            bool: True if domain was removed successfully, False if not found
        """
        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM blocked_domains 
                    WHERE child_id = (SELECT id FROM children WHERE name = ?) 
                    AND domain = ?
                ''', (child_name, domain.lower().strip()))

                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Removed blocked domain {domain} from {child_name}")
                return success

        except Exception as e:
            logger.error(f"Error removing blocked domain: {e}")
            return False

    def get_child_blocked_domains_set(self, child_name: str) -> Set[str]:
        """
        Get blocked domains for a child as a set (compatible with existing code)

        Args:
            child_name (str): Name of the child

        Returns:
            Set[str]: Set of blocked domain names
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT bd.domain 
                    FROM blocked_domains bd
                    JOIN children c ON bd.child_id = c.id
                    WHERE c.name = ?
                ''', (child_name,))

                return set(row['domain'] for row in cursor.fetchall())

        except Exception as e:
            logger.error(f"Error getting blocked domains for {child_name}: {e}")
            return set()

    def get_child_blocked_domains_list(self, child_name: str) -> List[str]:
        """
        Get blocked domains for a child as a sorted list

        Args:
            child_name (str): Name of the child

        Returns:
            List[str]: Sorted list of blocked domain names
        """
        domains = list(self.get_child_blocked_domains_set(child_name))
        domains.sort()
        return domains

    # ===============================
    # Browsing History Management Functions
    # ===============================

    def add_browsing_history(self, child_name: str, entries: List[Dict]) -> None:
        """
        Add browsing history entries for a child

        Automatically manages history size by keeping only the most recent
        5000 entries per child.

        Args:
            child_name (str): Name of the child
            entries (List[Dict]): List of browsing history entries
                Each entry should contain:
                - original_domain or domain: The accessed domain
                - main_domain (optional): Main domain name
                - display_name (optional): User-friendly site name
                - was_blocked (optional): Whether the site was blocked
                - timestamp (optional): Access timestamp
        """
        if not entries:
            return

        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()

                # Get child ID
                cursor.execute('SELECT id FROM children WHERE name = ?', (child_name,))
                result = cursor.fetchone()
                if not result:
                    logger.warning(f"Child {child_name} not found for history")
                    return

                child_id = result['id']

                # Add all entries
                for entry in entries:
                    try:
                        # Parse timestamp
                        timestamp_str = entry.get('timestamp', '')
                        timestamp = None

                        if timestamp_str:
                            try:
                                if 'T' in timestamp_str:
                                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                else:
                                    timestamp = datetime.fromisoformat(timestamp_str)
                            except:
                                timestamp = datetime.now()
                        else:
                            timestamp = datetime.now()

                        cursor.execute('''
                            INSERT INTO browsing_history 
                            (child_id, original_domain, main_domain, display_name, was_blocked, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            child_id,
                            entry.get('original_domain', entry.get('domain', '')),
                            entry.get('main_domain', ''),
                            entry.get('display_name', ''),
                            entry.get('was_blocked', False),
                            timestamp
                        ))

                    except Exception as e:
                        logger.warning(f"Failed to add history entry: {e}")

                # Limit to 5000 entries per child (keep most recent)
                cursor.execute('''
                    DELETE FROM browsing_history 
                    WHERE child_id = ? AND id NOT IN (
                        SELECT id FROM browsing_history 
                        WHERE child_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT 5000
                    )
                ''', (child_id, child_id))

                logger.info(f"Added {len(entries)} history entries for {child_name}")

        except Exception as e:
            logger.error(f"Error adding browsing history: {e}")

    def get_browsing_history(self, child_filter: Optional[str] = None,
                             status_filter: Optional[str] = None,
                             domain_filter: Optional[str] = None,
                             limit: int = 200) -> List[Dict]:
        """
        Get browsing history with optional filters

        Fixed: Returns list of entries instead of dictionary organized by child

        Args:
            child_filter (Optional[str]): Filter by specific child name
            status_filter (Optional[str]): Filter by 'blocked' or 'allowed'
            domain_filter (Optional[str]): Filter by domain name substring
            limit (int): Maximum number of entries to return

        Returns:
            List[Dict]: List of history entries with all fields
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Build dynamic query
                query = '''
                    SELECT c.name as child_name, bh.original_domain, bh.main_domain, 
                           bh.display_name, bh.was_blocked, bh.timestamp,
                           bh.original_domain as domain
                    FROM browsing_history bh
                    JOIN children c ON bh.child_id = c.id
                    WHERE 1=1
                '''
                params = []

                if child_filter:
                    query += ' AND c.name = ?'
                    params.append(child_filter)

                if status_filter == 'blocked':
                    query += ' AND bh.was_blocked = 1'
                elif status_filter == 'allowed':
                    query += ' AND bh.was_blocked = 0'

                if domain_filter:
                    query += ' AND (bh.original_domain LIKE ? OR bh.display_name LIKE ? OR bh.main_domain LIKE ?)'
                    params.extend([f'%{domain_filter}%', f'%{domain_filter}%', f'%{domain_filter}%'])

                query += ' ORDER BY bh.timestamp DESC LIMIT ?'
                params.append(limit)

                cursor.execute(query, params)

                # Convert rows to list of dicts
                results = []
                for row in cursor.fetchall():
                    # Ensure timestamp is string
                    timestamp = row['timestamp']
                    if hasattr(timestamp, 'isoformat'):
                        timestamp = timestamp.isoformat()

                    entry = {
                        'child_name': row['child_name'],
                        'original_domain': row['original_domain'],
                        'domain': row['original_domain'],  # For compatibility
                        'main_domain': row['main_domain'] or row['original_domain'],
                        'display_name': row['display_name'] or row['original_domain'],
                        'was_blocked': bool(row['was_blocked']),
                        'timestamp': timestamp
                    }
                    results.append(entry)

                logger.debug(f"Retrieved {len(results)} history entries from database")
                return results

        except Exception as e:
            logger.error(f"Error getting browsing history: {e}")
            import traceback
            traceback.print_exc()
            return []

    def clear_child_history(self, child_name: str) -> bool:
        """
        Clear all browsing history for a specific child

        Args:
            child_name (str): Name of the child

        Returns:
            bool: True if history was cleared successfully, False if child not found
        """
        try:
            with self._lock, self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM browsing_history 
                    WHERE child_id = (SELECT id FROM children WHERE name = ?)
                ''', (child_name,))

                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Cleared history for {child_name}")
                return success

        except Exception as e:
            logger.error(f"Error clearing history: {e}")
            return False


# ===============================
# Global Instance and Helper Functions
# ===============================

# Global database manager instance
db_manager = None


def initialize_database(db_path: str = "parental_control.db") -> DatabaseManager:
    """
    Initialize the global database manager instance

    Args:
        db_path (str): Path to the SQLite database file

    Returns:
        DatabaseManager: Initialized database manager instance
    """
    global db_manager
    db_manager = DatabaseManager(db_path)
    logger.info("Global database manager initialized")
    return db_manager


def get_database() -> DatabaseManager:
    """
    Get the global database manager instance

    Returns:
        DatabaseManager: Global database manager instance

    Raises:
        RuntimeError: If database manager is not initialized
    """
    global db_manager
    if db_manager is None:
        db_manager = initialize_database()
    return db_manager


# ===============================
# Compatibility Functions for Existing Code
# ===============================

def save_children_data() -> None:
    """
    Compatibility function - data is automatically saved in database

    This function exists for compatibility with existing code that
    called save_children_data(). In the database version, all changes
    are automatically committed, so this function does nothing.
    """
    pass  # Data is automatically saved in database


def load_children_data() -> Dict[str, Dict]:
    """
    Compatibility function - loads children data from database

    Returns:
        Dict[str, Dict]: Children data in the same format as the old JSON system
    """
    return get_database().get_all_children()


def save_browsing_history() -> None:
    """
    Compatibility function - data is automatically saved in database

    This function exists for compatibility with existing code that
    called save_browsing_history(). In the database version, all changes
    are automatically committed, so this function does nothing.
    """
    pass  # Data is automatically saved in database


def load_browsing_history() -> Dict[str, List]:
    """
    Compatibility function - loads browsing history from database

    Returns:
        Dict[str, List]: Browsing history data in the same format as the old JSON system
    """
    return get_database().get_browsing_history()


# ===============================
# Database Migration and Utilities
# ===============================

def migrate_from_json(users_file: str = "users_data.json",
                      children_file: str = "children_data.json",
                      history_file: str = "browsing_history.json") -> bool:
    """
    Migrate data from existing JSON files to SQLite database

    Args:
        users_file (str): Path to users JSON file
        children_file (str): Path to children JSON file
        history_file (str): Path to browsing history JSON file

    Returns:
        bool: True if migration was successful, False otherwise
    """
    try:
        db = get_database()
        success = True

        # Migrate users
        if os.path.exists(users_file):
            with open(users_file, 'r', encoding='utf-8') as f:
                users_data = json.load(f)

            for email, user_info in users_data.items():
                # Create user with existing hash (no re-hashing needed)
                with db._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO users (email, fullname, password_hash)
                        VALUES (?, ?, ?)
                    ''', (email, user_info['fullname'], user_info['password_hash']))

            logger.info(f"Migrated {len(users_data)} users")

        # Migrate children and blocked domains
        if os.path.exists(children_file):
            with open(children_file, 'r', encoding='utf-8') as f:
                children_data = json.load(f)

            for child_name, child_info in children_data.items():
                # Add child
                db.add_child(child_name)

                # Add blocked domains
                blocked_domains = child_info.get('blocked_domains', [])
                for domain in blocked_domains:
                    db.add_blocked_domain(child_name, domain)

                # Update connection info if available
                if child_info.get('last_seen'):
                    db.update_child_connection(
                        child_name,
                        child_info.get('client_address'),
                        child_info.get('last_seen')
                    )

            logger.info(f"Migrated {len(children_data)} children")

        # Migrate browsing history
        if os.path.exists(history_file):
            with open(history_file, 'r', encoding='utf-8') as f:
                history_data = json.load(f)

            for child_name, entries in history_data.items():
                if child_name == "security_alerts":  # Skip security alerts for now
                    continue

                if entries and isinstance(entries, list):
                    db.add_browsing_history(child_name, entries)

            logger.info("Migrated browsing history")

        logger.info(" Migration from JSON files completed successfully")
        return True

    except Exception as e:
        logger.error(f" Migration failed: {e}")
        return False


def export_to_json(output_dir: str = "database_export") -> bool:
    """
    Export database contents to JSON files for backup or analysis

    Args:
        output_dir (str): Directory to save exported JSON files

    Returns:
        bool: True if export was successful, False otherwise
    """
    try:
        import os
        os.makedirs(output_dir, exist_ok=True)

        db = get_database()

        # Export users
        with db._get_connection() as conn:
            cursor = conn.cursor()

            # Users export
            cursor.execute('SELECT email, fullname, password_hash, created_at FROM users')
            users_data = {}
            for row in cursor.fetchall():
                users_data[row['email']] = {
                    'fullname': row['fullname'],
                    'password_hash': row['password_hash'],
                    'created_at': row['created_at']
                }

            with open(f"{output_dir}/users_export.json", 'w', encoding='utf-8') as f:
                json.dump(users_data, f, indent=2, ensure_ascii=False)

            # Children export
            children_data = db.get_all_children()
            # Convert sets to lists for JSON serialization
            for child_name, child_info in children_data.items():
                child_info['blocked_domains'] = list(child_info['blocked_domains'])

            with open(f"{output_dir}/children_export.json", 'w', encoding='utf-8') as f:
                json.dump(children_data, f, indent=2, ensure_ascii=False)

            # History export
            history_data = db.get_browsing_history(limit=10000)
            with open(f"{output_dir}/history_export.json", 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2, ensure_ascii=False)

            # Security alerts export
            alerts = db.get_security_alerts(limit=1000)
            with open(f"{output_dir}/security_alerts_export.json", 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)

        logger.info(f" Database exported to {output_dir}/")
        return True

    except Exception as e:
        logger.error(f" Export failed: {e}")
        return False


def get_database_statistics() -> Dict:
    """
    Get comprehensive database statistics

    Returns:
        Dict: Database statistics including counts and sizes
    """
    try:
        db = get_database()
        stats = {}

        with db._get_connection() as conn:
            cursor = conn.cursor()

            # Table counts
            cursor.execute('SELECT COUNT(*) FROM users')
            stats['users_count'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM children WHERE is_active = 1')
            stats['children_count'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM blocked_domains')
            stats['blocked_domains_count'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM browsing_history')
            stats['browsing_history_count'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM security_alerts')
            stats['security_alerts_count'] = cursor.fetchone()[0]

            # Additional statistics
            cursor.execute('''
                SELECT c.name, COUNT(bd.id) as domain_count
                FROM children c
                LEFT JOIN blocked_domains bd ON c.id = bd.child_id
                WHERE c.is_active = 1
                GROUP BY c.id, c.name
            ''')
            stats['domains_per_child'] = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute('''
                SELECT c.name, COUNT(bh.id) as history_count
                FROM children c
                LEFT JOIN browsing_history bh ON c.id = bh.child_id
                WHERE c.is_active = 1
                GROUP BY c.id, c.name
            ''')
            stats['history_per_child'] = {row[0]: row[1] for row in cursor.fetchall()}

            # Database file size
            try:
                import os
                stats['database_size_bytes'] = os.path.getsize(db.db_path)
                stats['database_size_mb'] = round(stats['database_size_bytes'] / (1024 * 1024), 2)
            except:
                stats['database_size_bytes'] = 0
                stats['database_size_mb'] = 0

        return stats

    except Exception as e:
        logger.error(f"Error getting database statistics: {e}")
        return {}


def cleanup_old_data(days_to_keep: int = 30) -> int:
    """
    Clean up old browsing history and security alerts

    Args:
        days_to_keep (int): Number of days of data to keep

    Returns:
        int: Number of records deleted
    """
    try:
        db = get_database()
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        deleted_count = 0

        with db._lock, db._get_connection() as conn:
            cursor = conn.cursor()

            # Clean old browsing history
            cursor.execute('''
                DELETE FROM browsing_history 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            deleted_count += cursor.rowcount

            # Clean old security alerts
            cursor.execute('''
                DELETE FROM security_alerts 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            deleted_count += cursor.rowcount

        logger.info(f"Cleaned up {deleted_count} old records (older than {days_to_keep} days)")
        return deleted_count

    except Exception as e:
        logger.error(f"Error cleaning up old data: {e}")
        return 0


def vacuum_database() -> bool:
    """
    Optimize database by running VACUUM command

    This reclaims unused space and optimizes the database file.

    Returns:
        bool: True if vacuum was successful, False otherwise
    """
    try:
        db = get_database()

        with db._get_connection() as conn:
            # Get size before vacuum
            cursor = conn.cursor()
            cursor.execute("PRAGMA page_count")
            pages_before = cursor.fetchone()[0]

            # Run vacuum
            conn.execute("VACUUM")

            # Get size after vacuum
            cursor.execute("PRAGMA page_count")
            pages_after = cursor.fetchone()[0]

            pages_freed = pages_before - pages_after
            logger.info(f"Database vacuumed: {pages_freed} pages freed")

        return True

    except Exception as e:
        logger.error(f"Error vacuuming database: {e}")
        return False


# ===============================
# Database Health Check Functions
# ===============================

def check_database_integrity() -> Dict[str, bool]:
    """
    Perform comprehensive database integrity check

    Returns:
        Dict[str, bool]: Results of various integrity checks
    """
    try:
        db = get_database()
        results = {}

        with db._get_connection() as conn:
            cursor = conn.cursor()

            # Check database integrity
            cursor.execute("PRAGMA integrity_check")
            integrity_result = cursor.fetchone()[0]
            results['integrity_check'] = integrity_result == 'ok'

            # Check foreign key constraints
            cursor.execute("PRAGMA foreign_key_check")
            fk_violations = cursor.fetchall()
            results['foreign_key_check'] = len(fk_violations) == 0

            # Check for orphaned records
            cursor.execute('''
                SELECT COUNT(*) FROM blocked_domains bd
                LEFT JOIN children c ON bd.child_id = c.id
                WHERE c.id IS NULL
            ''')
            orphaned_domains = cursor.fetchone()[0]
            results['no_orphaned_domains'] = orphaned_domains == 0

            cursor.execute('''
                SELECT COUNT(*) FROM browsing_history bh
                LEFT JOIN children c ON bh.child_id = c.id
                WHERE c.id IS NULL
            ''')
            orphaned_history = cursor.fetchone()[0]
            results['no_orphaned_history'] = orphaned_history == 0

            # Check for duplicate children
            cursor.execute('''
                SELECT COUNT(*) FROM (
                    SELECT name FROM children 
                    GROUP BY name 
                    HAVING COUNT(*) > 1
                )
            ''')
            duplicate_children = cursor.fetchone()[0]
            results['no_duplicate_children'] = duplicate_children == 0

        logger.info(f"Database integrity check completed: {results}")
        return results

    except Exception as e:
        logger.error(f"Error checking database integrity: {e}")
        return {'error': True, 'message': str(e)}


if __name__ == "__main__":
    """
    Module test and demonstration
    """
    print(" SQLite Database Manager for Parental Control System")
    print("=" * 60)

    # Initialize database
    print(" Initializing database...")
    db = initialize_database("test_parental_control.db")

    # Test basic operations
    print(" Testing basic operations...")

    # Test user registration
    success, msg = db.register_user("test@example.com", "Test User", "password123")
    print(f"User registration: {'yes' if success else 'no'} {msg}")

    # Test user login
    login_valid = db.validate_login("test@example.com", "password123")
    print(f"User login: {'yes' if login_valid else 'no'}")

    # Test child management
    child_added = db.add_child("Test Child")
    print(f"Add child: {'yes' if child_added else 'no'}")

    # Test blocked domains
    domain_added = db.add_blocked_domain("Test Child", "example.com")
    print(f"Add blocked domain: {'yes' if domain_added else 'no'}")

    # Test browsing history
    test_history = [{
        'original_domain': 'test.com',
        'display_name': 'Test Site',
        'was_blocked': False,
        'timestamp': datetime.now().isoformat()
    }]
    db.add_browsing_history("Test Child", test_history)
    print(" Browsing history added")

    # Get statistics
    stats = get_database_statistics()
    print(f"\n Database Statistics:")
    print(f"   Users: {stats.get('users_count', 0)}")
    print(f"   Children: {stats.get('children_count', 0)}")
    print(f"   Blocked domains: {stats.get('blocked_domains_count', 0)}")
    print(f"   History entries: {stats.get('browsing_history_count', 0)}")
    print(f"   Database size: {stats.get('database_size_mb', 0)} MB")

    # Check integrity
    integrity = check_database_integrity()
    all_good = all(integrity.values()) if 'error' not in integrity else False
    print(f"\n Database Integrity: {' All checks passed' if all_good else 'Issues found'}")

    print("\n Database manager test completed!")
    print(" Ready for integration with parental control system")