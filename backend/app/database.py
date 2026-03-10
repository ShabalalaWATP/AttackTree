from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings
from .services.auth import hash_password


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)

if "sqlite" in settings.DATABASE_URL:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if "sqlite" in settings.DATABASE_URL:
            await _migrate_scenarios_table(conn)
            await _migrate_multi_user_tables(conn)

    admin_user_id = await _ensure_seed_users()
    if "sqlite" in settings.DATABASE_URL:
        await _backfill_multi_user_ownership(admin_user_id)


async def _migrate_scenarios_table(conn) -> None:
    table_exists = await conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scenarios'"
    )
    if table_exists.first() is None:
        return

    pragma = await conn.exec_driver_sql("PRAGMA table_info(scenarios)")
    columns = {
        row[1]: {
            "type": row[2],
            "notnull": row[3],
        }
        for row in pragma.fetchall()
    }

    required_columns = {
        "scope",
        "scenario_type",
        "operation_goal",
        "target_profile",
        "target_environment",
        "execution_tempo",
        "stealth_level",
        "access_level",
        "entry_vectors",
        "campaign_phases",
        "constraints",
        "dependencies",
        "intelligence_gaps",
        "success_criteria",
        "focus_node_ids",
        "focus_tags",
        "degraded_detections",
        "planning_notes",
    }
    needs_migration = (
        columns.get("project_id", {}).get("notnull") == 1
        or not required_columns.issubset(columns)
    )
    if not needs_migration:
        return

    await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
    try:
        await conn.exec_driver_sql("DROP TABLE IF EXISTS scenarios_new")
        await conn.exec_driver_sql(
            """
            CREATE TABLE scenarios_new (
                id VARCHAR(36) PRIMARY KEY NOT NULL,
                project_id VARCHAR(36),
                scope VARCHAR(20),
                name VARCHAR(255) NOT NULL,
                description TEXT,
                status VARCHAR(20),
                scenario_type VARCHAR(50),
                operation_goal TEXT,
                target_profile VARCHAR(255),
                target_environment VARCHAR(255),
                execution_tempo VARCHAR(20),
                stealth_level VARCHAR(20),
                access_level VARCHAR(30),
                attacker_type VARCHAR(50),
                attacker_skill VARCHAR(20),
                attacker_resources VARCHAR(20),
                attacker_motivation VARCHAR(100),
                entry_vectors JSON,
                campaign_phases JSON,
                constraints JSON,
                dependencies JSON,
                intelligence_gaps JSON,
                success_criteria JSON,
                focus_node_ids JSON,
                focus_tags JSON,
                disabled_controls JSON,
                degraded_detections JSON,
                modified_scores JSON,
                assumptions TEXT,
                planning_notes TEXT,
                ai_narrative TEXT,
                ai_recommendations JSON,
                impact_summary JSON,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE
            )
            """
        )

        scope_expr = (
            "COALESCE(scope, CASE WHEN project_id IS NULL THEN 'standalone' ELSE 'project' END)"
            if "scope" in columns
            else "CASE WHEN project_id IS NULL THEN 'standalone' ELSE 'project' END"
        )

        def col(name: str, fallback: str) -> str:
            return f"COALESCE({name}, {fallback})" if name in columns else fallback

        await conn.exec_driver_sql(
            f"""
            INSERT INTO scenarios_new (
                id, project_id, scope, name, description, status,
                scenario_type, operation_goal, target_profile, target_environment,
                execution_tempo, stealth_level, access_level,
                attacker_type, attacker_skill, attacker_resources, attacker_motivation,
                entry_vectors, campaign_phases, constraints, dependencies,
                intelligence_gaps, success_criteria, focus_node_ids, focus_tags,
                disabled_controls, degraded_detections, modified_scores,
                assumptions, planning_notes, ai_narrative, ai_recommendations,
                impact_summary, created_at, updated_at
            )
            SELECT
                id,
                project_id,
                {scope_expr},
                name,
                {col('description', "''")},
                {col('status', "'draft'")},
                {col('scenario_type', "'campaign'")},
                {col('operation_goal', "''")},
                {col('target_profile', "''")},
                {col('target_environment', "''")},
                {col('execution_tempo', "'balanced'")},
                {col('stealth_level', "'balanced'")},
                {col('access_level', "'external'")},
                {col('attacker_type', "'opportunistic'")},
                {col('attacker_skill', "'Medium'")},
                {col('attacker_resources', "'Medium'")},
                {col('attacker_motivation', "''")},
                {col('entry_vectors', "'[]'")},
                {col('campaign_phases', "'[]'")},
                {col('constraints', "'[]'")},
                {col('dependencies', "'[]'")},
                {col('intelligence_gaps', "'[]'")},
                {col('success_criteria', "'[]'")},
                {col('focus_node_ids', "'[]'")},
                {col('focus_tags', "'[]'")},
                {col('disabled_controls', "'[]'")},
                {col('degraded_detections', "'[]'")},
                {col('modified_scores', "'{{}}'")},
                {col('assumptions', "''")},
                {col('planning_notes', "''")},
                {col('ai_narrative', "''")},
                {col('ai_recommendations', "'[]'")},
                {col('impact_summary', "'{{}}'")},
                {col('created_at', 'CURRENT_TIMESTAMP')},
                {col('updated_at', 'CURRENT_TIMESTAMP')}
            FROM scenarios
            """
        )
        await conn.exec_driver_sql("DROP TABLE scenarios")
        await conn.exec_driver_sql("ALTER TABLE scenarios_new RENAME TO scenarios")
    finally:
        await conn.exec_driver_sql("PRAGMA foreign_keys=ON")


async def _migrate_multi_user_tables(conn) -> None:
    await _ensure_column(conn, "users", "username", "VARCHAR(100)")
    await _ensure_column(conn, "projects", "user_id", "VARCHAR(36)")
    await _ensure_column(conn, "llm_provider_configs", "user_id", "VARCHAR(36)")
    await _ensure_column(conn, "llm_job_history", "user_id", "VARCHAR(36)")
    await _ensure_column(conn, "scenarios", "user_id", "VARCHAR(36)")
    await _ensure_column(conn, "infra_maps", "user_id", "VARCHAR(36)")
    await _migrate_tags_table(conn)

    await conn.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username)")
    await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects (user_id)")
    await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_llm_provider_user_id ON llm_provider_configs (user_id)")
    await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_llm_job_user_id ON llm_job_history (user_id)")
    await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_scenarios_user_id ON scenarios (user_id)")
    await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_infra_maps_user_id ON infra_maps (user_id)")
    await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_tags_user_id ON tags (user_id)")


async def _ensure_column(conn, table_name: str, column_name: str, column_type: str) -> None:
    table_exists = await conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    )
    if table_exists.first() is None:
        return

    pragma = await conn.exec_driver_sql(f"PRAGMA table_info({table_name})")
    existing_columns = {row[1] for row in pragma.fetchall()}
    if column_name in existing_columns:
        return

    await conn.exec_driver_sql(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    )


async def _migrate_tags_table(conn) -> None:
    table_exists = await conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tags'"
    )
    if table_exists.first() is None:
        return

    pragma = await conn.exec_driver_sql("PRAGMA table_info(tags)")
    columns = {row[1] for row in pragma.fetchall()}
    if "user_id" in columns:
        return

    await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
    try:
        await conn.exec_driver_sql("DROP TABLE IF EXISTS tags_new")
        await conn.exec_driver_sql(
            """
            CREATE TABLE tags_new (
                id VARCHAR(36) PRIMARY KEY NOT NULL,
                user_id VARCHAR(36),
                name VARCHAR(100) NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(user_id, name)
            )
            """
        )
        await conn.exec_driver_sql(
            """
            INSERT INTO tags_new (id, name)
            SELECT id, name
            FROM tags
            """
        )
        await conn.exec_driver_sql("DROP TABLE tags")
        await conn.exec_driver_sql("ALTER TABLE tags_new RENAME TO tags")
    finally:
        await conn.exec_driver_sql("PRAGMA foreign_keys=ON")


async def _ensure_seed_users() -> str:
    from .models.user import User

    default_users = [
        {
            "name": "adminaccount",
            "username": "admin12345",
            "email": "adminaccount@attacktree.local",
            "password": "admin12345",
            "role": "admin",
            "password_reset_required": False,
        },
        {
            "name": "Administrator",
            "username": "administrator",
            "email": "admin@attacktree.local",
            "password": "AdminPass!234",
            "role": "admin",
            "password_reset_required": False,
        },
        {
            "name": "Alice Research",
            "username": "alice",
            "email": "alice@attacktree.local",
            "password": "ChangeMe!101",
            "role": "user",
            "password_reset_required": True,
        },
        {
            "name": "Bob Reverse",
            "username": "bob",
            "email": "bob@attacktree.local",
            "password": "ChangeMe!102",
            "role": "user",
            "password_reset_required": True,
        },
        {
            "name": "Carol Operator",
            "username": "carol",
            "email": "carol@attacktree.local",
            "password": "ChangeMe!103",
            "role": "user",
            "password_reset_required": True,
        },
        {
            "name": "Dan Analyst",
            "username": "dan",
            "email": "dan@attacktree.local",
            "password": "ChangeMe!104",
            "role": "user",
            "password_reset_required": True,
        },
        {
            "name": "Erin Planner",
            "username": "erin",
            "email": "erin@attacktree.local",
            "password": "ChangeMe!105",
            "role": "user",
            "password_reset_required": True,
        },
    ]

    async with async_session_factory() as session:
        await _backfill_usernames(session)
        existing = {
            email.lower(): user_id
            for email, user_id in (await session.execute(select(User.email, User.id))).all()
        }
        existing_usernames = {
            username.lower(): user_id
            for username, user_id in (await session.execute(select(User.username, User.id))).all()
            if username
        }
        admin_id = existing.get("adminaccount@attacktree.local") or existing.get("admin@attacktree.local")

        for seed in default_users:
            if seed["email"].lower() in existing or seed["username"].lower() in existing_usernames:
                continue
            user = User(
                name=seed["name"],
                username=seed["username"].lower(),
                email=seed["email"].lower(),
                password_hash=hash_password(seed["password"]),
                role=seed["role"],
                is_active=True,
                password_reset_required=seed["password_reset_required"],
            )
            session.add(user)
            await session.flush()
            existing[user.email] = user.id
            existing_usernames[user.username] = user.id
            if user.email in {"adminaccount@attacktree.local", "admin@attacktree.local"}:
                admin_id = user.id

        await session.commit()

    if not admin_id:
        async with async_session_factory() as session:
            result = await session.execute(
                select(User.id).where(User.username.in_(["admin12345", "administrator"]))
            )
            admin_id = result.scalar_one()
    return admin_id


async def _backfill_multi_user_ownership(admin_user_id: str) -> None:
    if not admin_user_id:
        return

    async with async_session_factory() as session:
        statements = [
            ("projects", "user_id"),
            ("llm_provider_configs", "user_id"),
            ("llm_job_history", "user_id"),
            ("scenarios", "user_id"),
            ("infra_maps", "user_id"),
            ("tags", "user_id"),
        ]
        for table_name, column_name in statements:
            await session.execute(
                text(f"UPDATE {table_name} SET {column_name} = :user_id WHERE {column_name} IS NULL"),
                {"user_id": admin_user_id},
            )
        await session.commit()


async def _backfill_usernames(session: AsyncSession) -> None:
    from .models.user import User

    users = (await session.execute(select(User))).scalars().all()
    used: set[str] = set()

    for user in users:
        if user.username:
            candidate = user.username.strip().lower()
            if candidate in used:
                candidate = _dedupe_username(candidate, used)
                user.username = candidate
            used.add(candidate)
            continue

        base = (user.email.split("@", 1)[0] if user.email else user.name).strip().lower()
        candidate = _sanitize_username(base or "user")
        if candidate in used:
            candidate = _dedupe_username(candidate, used)
        user.username = candidate
        used.add(candidate)

    await session.commit()


def _sanitize_username(value: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
    candidate = "".join(char for char in value if char in allowed)
    return candidate or "user"


def _dedupe_username(base: str, used: set[str]) -> str:
    suffix = 2
    candidate = base
    while candidate in used:
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate
