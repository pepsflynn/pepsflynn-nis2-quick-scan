"""
db.py — NIS2 Portal: database SQLite helpers
Tabelle: enterprises, suppliers, tasks, submissions
"""
import sqlite3
import hashlib
import secrets
import os
import json
from contextlib import contextmanager

DB_PATH = os.environ.get('DB_PATH', 'nis2_portal.db')
_SALT   = 'nis2_ichnobyte_2024'


# ─────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS enterprises (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                category      TEXT DEFAULT 'Importante',
                ateco         TEXT DEFAULT '',
                created_at    TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS suppliers (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                enterprise_id INTEGER NOT NULL,
                name          TEXT NOT NULL,
                email         TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                access_code   TEXT UNIQUE NOT NULL,
                contact_name  TEXT DEFAULT '',
                ateco         TEXT DEFAULT '',
                notes         TEXT DEFAULT '',
                domain        TEXT DEFAULT '',
                created_at    TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (enterprise_id) REFERENCES enterprises(id)
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                supplier_id   INTEGER NOT NULL,
                enterprise_id INTEGER NOT NULL,
                type          TEXT NOT NULL,
                title         TEXT NOT NULL,
                description   TEXT DEFAULT '',
                due_date      TEXT DEFAULT '',
                priority      TEXT DEFAULT 'media',
                status        TEXT DEFAULT 'assegnato',
                created_at    TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (supplier_id)   REFERENCES suppliers(id),
                FOREIGN KEY (enterprise_id) REFERENCES enterprises(id)
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id      INTEGER NOT NULL,
                supplier_id  INTEGER NOT NULL,
                answers      TEXT NOT NULL,
                score        REAL DEFAULT 0,
                score_pct    REAL DEFAULT 0,
                notes        TEXT DEFAULT '',
                submitted_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (task_id)     REFERENCES tasks(id),
                FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
            );
        """)


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(f"{_SALT}{password}".encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def generate_access_code() -> str:
    h = secrets.token_hex(4).upper()
    return f"ICH-{h[:4]}-{h[4:]}"


# ─────────────────────────────────────────────
# Enterprise
# ─────────────────────────────────────────────

def create_enterprise(name, email, password, category='Importante', ateco=''):
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO enterprises (name,email,password_hash,category,ateco) VALUES (?,?,?,?,?)",
                (name, email, hash_password(password), category, ateco)
            )
            return True, None
        except sqlite3.IntegrityError:
            return False, "Email già registrata"

def get_enterprise_by_email(email):
    with get_db() as db:
        return db.execute("SELECT * FROM enterprises WHERE email=?", (email,)).fetchone()

def get_enterprise_by_id(eid):
    with get_db() as db:
        return db.execute("SELECT * FROM enterprises WHERE id=?", (eid,)).fetchone()


# ─────────────────────────────────────────────
# Supplier
# ─────────────────────────────────────────────

def create_supplier(enterprise_id, name, email, password,
                    contact_name='', ateco='', notes='', domain=''):
    code = generate_access_code()
    with get_db() as db:
        try:
            cur = db.execute(
                """INSERT INTO suppliers
                   (enterprise_id,name,email,password_hash,access_code,
                    contact_name,ateco,notes,domain)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (enterprise_id, name, email, hash_password(password), code,
                 contact_name, ateco, notes, domain)
            )
            return cur.lastrowid, code, None
        except sqlite3.IntegrityError:
            code = generate_access_code()
            cur = db.execute(
                """INSERT INTO suppliers
                   (enterprise_id,name,email,password_hash,access_code,
                    contact_name,ateco,notes,domain)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (enterprise_id, name, email, hash_password(password), code,
                 contact_name, ateco, notes, domain)
            )
            return cur.lastrowid, code, None

def get_suppliers_by_enterprise(enterprise_id):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM suppliers WHERE enterprise_id=? ORDER BY name",
            (enterprise_id,)
        ).fetchall()

def get_supplier_by_id(sid):
    with get_db() as db:
        return db.execute("SELECT * FROM suppliers WHERE id=?", (sid,)).fetchone()

def get_supplier_by_email(email):
    with get_db() as db:
        return db.execute("SELECT * FROM suppliers WHERE email=?", (email,)).fetchone()

def get_supplier_by_access_code(code):
    with get_db() as db:
        return db.execute("SELECT * FROM suppliers WHERE access_code=?", (code,)).fetchone()

def delete_supplier(sid):
    with get_db() as db:
        db.execute("DELETE FROM tasks WHERE supplier_id=?", (sid,))
        db.execute("DELETE FROM suppliers WHERE id=?", (sid,))


# ─────────────────────────────────────────────
# Tasks
# ─────────────────────────────────────────────

def create_task(supplier_id, enterprise_id, task_type, title,
                description='', due_date='', priority='media'):
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO tasks
               (supplier_id,enterprise_id,type,title,description,due_date,priority)
               VALUES (?,?,?,?,?,?,?)""",
            (supplier_id, enterprise_id, task_type, title,
             description, due_date, priority)
        )
        return cur.lastrowid

def get_tasks_by_supplier(supplier_id):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM tasks WHERE supplier_id=? ORDER BY created_at DESC",
            (supplier_id,)
        ).fetchall()

def get_tasks_by_enterprise_supplier(enterprise_id, supplier_id):
    with get_db() as db:
        return db.execute(
            """SELECT t.*, s.submitted_at as sub_at
               FROM tasks t
               LEFT JOIN submissions s ON s.task_id = t.id
               WHERE t.enterprise_id=? AND t.supplier_id=?
               ORDER BY t.created_at DESC""",
            (enterprise_id, supplier_id)
        ).fetchall()

def get_task_by_id(task_id):
    with get_db() as db:
        return db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()

def update_task_status(task_id, status):
    with get_db() as db:
        db.execute("UPDATE tasks SET status=? WHERE id=?", (status, task_id))

def delete_task(task_id):
    with get_db() as db:
        db.execute("DELETE FROM submissions WHERE task_id=?", (task_id,))
        db.execute("DELETE FROM tasks WHERE id=?", (task_id,))


# ─────────────────────────────────────────────
# Submissions
# ─────────────────────────────────────────────

def create_submission(task_id, supplier_id, answers_dict, score, score_pct, notes=''):
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO submissions (task_id,supplier_id,answers,score,score_pct,notes) VALUES (?,?,?,?,?,?)",
            (task_id, supplier_id, json.dumps(answers_dict), score, score_pct, notes)
        )
        return cur.lastrowid

def get_submission_by_task(task_id):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM submissions WHERE task_id=? ORDER BY submitted_at DESC LIMIT 1",
            (task_id,)
        ).fetchone()
        if row:
            d = dict(row)
            try:
                d['answers'] = json.loads(d['answers'])
            except Exception:
                d['answers'] = {}
            return d
        return None

def get_all_submissions_by_enterprise(enterprise_id):
    with get_db() as db:
        return db.execute(
            """SELECT sub.*, t.title, t.type, s.name as supplier_name
               FROM submissions sub
               JOIN tasks t ON t.id = sub.task_id
               JOIN suppliers s ON s.id = sub.supplier_id
               WHERE t.enterprise_id=?
               ORDER BY sub.submitted_at DESC""",
            (enterprise_id,)
        ).fetchall()


# ─────────────────────────────────────────────
# Dashboard stats
# ─────────────────────────────────────────────

def get_enterprise_stats(enterprise_id):
    with get_db() as db:
        n_sup   = db.execute("SELECT COUNT(*) as n FROM suppliers WHERE enterprise_id=?", (enterprise_id,)).fetchone()['n']
        n_tasks = db.execute("SELECT COUNT(*) as n FROM tasks WHERE enterprise_id=?", (enterprise_id,)).fetchone()['n']
        n_done  = db.execute("SELECT COUNT(*) as n FROM tasks WHERE enterprise_id=? AND status='completato'", (enterprise_id,)).fetchone()['n']
        n_pend  = db.execute("SELECT COUNT(*) as n FROM tasks WHERE enterprise_id=? AND status='assegnato'", (enterprise_id,)).fetchone()['n']
        avg_score = db.execute(
            """SELECT AVG(sub.score_pct) as avg
               FROM submissions sub
               JOIN tasks t ON t.id=sub.task_id
               WHERE t.enterprise_id=?""",
            (enterprise_id,)
        ).fetchone()['avg']
        return {
            'suppliers': n_sup,
            'tasks_total': n_tasks,
            'tasks_done': n_done,
            'tasks_pending': n_pend,
            'avg_score': round(avg_score or 0, 1)
        }

def get_supplier_stats(supplier_id):
    with get_db() as db:
        n_tasks = db.execute("SELECT COUNT(*) as n FROM tasks WHERE supplier_id=?", (supplier_id,)).fetchone()['n']
        n_done  = db.execute("SELECT COUNT(*) as n FROM tasks WHERE supplier_id=? AND status='completato'", (supplier_id,)).fetchone()['n']
        n_pend  = db.execute("SELECT COUNT(*) as n FROM tasks WHERE supplier_id=? AND status='assegnato'", (supplier_id,)).fetchone()['n']
        return {'tasks_total': n_tasks, 'tasks_done': n_done, 'tasks_pending': n_pend}


# ─────────────────────────────────────────────
# Export / Import
# ─────────────────────────────────────────────

def export_enterprise_data(enterprise_id):
    """
    Esporta tutti i dati di un'enterprise in un dizionario serializzabile.
    Include: enterprise, suppliers, tasks, submissions.
    """
    from datetime import datetime
    with get_db() as db:
        ent = dict(db.execute(
            "SELECT * FROM enterprises WHERE id=?", (enterprise_id,)
        ).fetchone())

        suppliers = []
        for sup_row in db.execute(
            "SELECT * FROM suppliers WHERE enterprise_id=? ORDER BY name",
            (enterprise_id,)
        ).fetchall():
            sup = dict(sup_row)
            tasks = []
            for task_row in db.execute(
                "SELECT * FROM tasks WHERE supplier_id=? ORDER BY created_at",
                (sup['id'],)
            ).fetchall():
                task = dict(task_row)
                sub_row = db.execute(
                    "SELECT * FROM submissions WHERE task_id=? ORDER BY submitted_at DESC LIMIT 1",
                    (task['id'],)
                ).fetchone()
                if sub_row:
                    sub = dict(sub_row)
                    try:
                        sub['answers'] = json.loads(sub['answers'])
                    except Exception:
                        pass
                    task['submission'] = sub
                tasks.append(task)
            sup['tasks'] = tasks
            suppliers.append(sup)

        return {
            'exported_at':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'schema_version': '1.0',
            'enterprise':    ent,
            'suppliers':     suppliers,
        }


def import_enterprise_data(data):
    """
    Importa dati esportati nel database corrente.
    - Se l'enterprise esiste (stessa email) la riusa, altrimenti la crea.
    - Evita duplicati su suppliers (access_code) e tasks (created_at + title).
    Restituisce (success: bool, message: str, counts: dict).
    """
    try:
        ent_data = data.get('enterprise', {})
        suppliers_data = data.get('suppliers', [])

        n_sup = n_task = n_sub = 0

        with get_db() as db:
            # ── Enterprise ────────────────────────────────
            existing_ent = db.execute(
                "SELECT id FROM enterprises WHERE email=?", (ent_data['email'],)
            ).fetchone()

            if existing_ent:
                ent_id = existing_ent['id']
            else:
                cur = db.execute(
                    """INSERT INTO enterprises
                       (name,email,password_hash,category,ateco,created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (ent_data['name'], ent_data['email'],
                     ent_data['password_hash'],
                     ent_data.get('category','Importante'),
                     ent_data.get('ateco',''),
                     ent_data.get('created_at',''))
                )
                ent_id = cur.lastrowid

            # ── Suppliers ─────────────────────────────────
            for sup_data in suppliers_data:
                existing_sup = db.execute(
                    "SELECT id FROM suppliers WHERE access_code=?",
                    (sup_data['access_code'],)
                ).fetchone()

                if existing_sup:
                    sup_id = existing_sup['id']
                else:
                    cur = db.execute(
                        """INSERT INTO suppliers
                           (enterprise_id,name,email,password_hash,access_code,
                            contact_name,ateco,notes,domain,created_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (ent_id,
                         sup_data['name'], sup_data['email'],
                         sup_data['password_hash'], sup_data['access_code'],
                         sup_data.get('contact_name',''),
                         sup_data.get('ateco',''),
                         sup_data.get('notes',''),
                         sup_data.get('domain',''),
                         sup_data.get('created_at',''))
                    )
                    sup_id = cur.lastrowid
                    n_sup += 1

                # ── Tasks ─────────────────────────────────
                for task_data in sup_data.get('tasks', []):
                    existing_task = db.execute(
                        """SELECT id FROM tasks
                           WHERE supplier_id=? AND type=? AND created_at=?""",
                        (sup_id, task_data['type'], task_data.get('created_at',''))
                    ).fetchone()

                    if existing_task:
                        task_id = existing_task['id']
                    else:
                        cur = db.execute(
                            """INSERT INTO tasks
                               (supplier_id,enterprise_id,type,title,description,
                                due_date,priority,status,created_at)
                               VALUES (?,?,?,?,?,?,?,?,?)""",
                            (sup_id, ent_id,
                             task_data['type'], task_data['title'],
                             task_data.get('description',''),
                             task_data.get('due_date',''),
                             task_data.get('priority','media'),
                             task_data.get('status','assegnato'),
                             task_data.get('created_at',''))
                        )
                        task_id = cur.lastrowid
                        n_task += 1

                    # ── Submission ────────────────────────
                    sub_data = task_data.get('submission')
                    if sub_data:
                        existing_sub = db.execute(
                            "SELECT id FROM submissions WHERE task_id=?", (task_id,)
                        ).fetchone()
                        if not existing_sub:
                            answers = sub_data.get('answers', {})
                            db.execute(
                                """INSERT INTO submissions
                                   (task_id,supplier_id,answers,score,score_pct,notes,submitted_at)
                                   VALUES (?,?,?,?,?,?,?)""",
                                (task_id, sup_id,
                                 json.dumps(answers, ensure_ascii=False),
                                 sub_data.get('score', 0),
                                 sub_data.get('score_pct', 0),
                                 sub_data.get('notes',''),
                                 sub_data.get('submitted_at',''))
                            )
                            n_sub += 1

        msg = (f"Importazione completata: {n_sup} fornitori, "
               f"{n_task} task, {n_sub} risposte ripristinati.")
        return True, msg, {'suppliers': n_sup, 'tasks': n_task, 'submissions': n_sub}

    except Exception as e:
        return False, f"Errore durante l'importazione: {str(e)}", {}
