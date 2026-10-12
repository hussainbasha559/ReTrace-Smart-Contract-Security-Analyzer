"""initial schema

Revision ID: 0001
Revises: 
"""
from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('users',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=254), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=10), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('last_login_at', sa.DateTime(), nullable=True),
    sa.CheckConstraint("role in ('user','admin')", name='ck_users_role'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('actor_user_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=60), nullable=False),
    sa.Column('resource_type', sa.String(length=30), nullable=False),
    sa.Column('resource_id', sa.String(length=64), nullable=True),
    sa.Column('outcome', sa.String(length=15), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('request_id', sa.String(length=36), nullable=True),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_actor', 'audit_logs', ['actor_user_id'], unique=False)
    op.create_index('ix_audit_timestamp', 'audit_logs', ['timestamp'], unique=False)
    op.create_table('projects',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('project_name', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('owner_user_id', 'project_name', name='uq_projects_owner_name')
    )
    op.create_table('usage_events',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('event_type', sa.String(length=40), nullable=False),
    sa.Column('resource_type', sa.String(length=30), nullable=False),
    sa.Column('resource_id', sa.Integer(), nullable=True),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_usage_owner_created', 'usage_events', ['owner_user_id', 'created_at'], unique=False)
    op.create_index('ix_usage_type', 'usage_events', ['event_type'], unique=False)
    op.create_table('user_sessions',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('csrf_token', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )
    op.create_index('ix_user_sessions_expires', 'user_sessions', ['expires_at'], unique=False)
    op.create_index('ix_user_sessions_user', 'user_sessions', ['user_id'], unique=False)
    op.create_table('uploaded_files',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('original_filename', sa.String(length=255), nullable=False),
    sa.Column('generated_storage_key', sa.String(length=64), nullable=False),
    sa.Column('file_size', sa.Integer(), nullable=False),
    sa.Column('file_hash', sa.String(length=64), nullable=False),
    sa.Column('detected_input_type', sa.String(length=30), nullable=False),
    sa.Column('upload_status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('deleted_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('generated_storage_key')
    )
    op.create_index('ix_files_hash', 'uploaded_files', ['file_hash'], unique=False)
    op.create_index('ix_files_owner_created', 'uploaded_files', ['owner_user_id', 'created_at'], unique=False)
    op.create_table('scans',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('uploaded_file_id', sa.Integer(), nullable=True),
    sa.Column('scan_type', sa.String(length=30), nullable=False),
    sa.Column('target_identifier', sa.String(length=80), nullable=False),
    sa.Column('target_name', sa.String(length=255), nullable=True),
    sa.Column('network_name', sa.String(length=50), nullable=True),
    sa.Column('scan_status', sa.String(length=12), nullable=False),
    sa.Column('run_decompiler', sa.Boolean(), nullable=False),
    sa.Column('run_mythril', sa.Boolean(), nullable=False),
    sa.Column('input_bytes', sa.Integer(), nullable=False),
    sa.Column('verdict', sa.String(length=30), nullable=True),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('analyzer_version', sa.String(length=40), nullable=False),
    sa.Column('error_summary', sa.Text(), nullable=True),
    sa.CheckConstraint("scan_status in ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED')", name='ck_scans_status'),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['uploaded_file_id'], ['uploaded_files.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scans_file', 'scans', ['uploaded_file_id'], unique=False)
    op.create_index('ix_scans_owner_created', 'scans', ['owner_user_id', 'created_at'], unique=False)
    op.create_index('ix_scans_owner_status', 'scans', ['owner_user_id', 'scan_status'], unique=False)
    op.create_table('ai_analysis',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('provider', sa.String(length=40), nullable=False),
    sa.Column('model_name', sa.String(length=80), nullable=True),
    sa.Column('analysis_type', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=15), nullable=False),
    sa.Column('result_summary', sa.String(length=500), nullable=True),
    sa.Column('result_text', sa.Text(), nullable=True),
    sa.Column('token_usage', sa.Integer(), nullable=True),
    sa.Column('prompt_tokens', sa.Integer(), nullable=True),
    sa.Column('completion_tokens', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_ai_owner_created', 'ai_analysis', ['owner_user_id', 'created_at'], unique=False)
    op.create_index('ix_ai_scan', 'ai_analysis', ['scan_id'], unique=False)
    op.create_table('scan_reports',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('report_kind', sa.String(length=30), nullable=False),
    sa.Column('report_format', sa.String(length=10), nullable=False),
    sa.Column('storage_key', sa.String(length=64), nullable=False),
    sa.Column('report_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('storage_key')
    )
    op.create_index('ix_reports_scan', 'scan_reports', ['scan_id'], unique=False)
    op.create_table('vulnerabilities',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('category', sa.String(length=120), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('swc_id', sa.String(length=20), nullable=True),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('severity', sa.String(length=15), nullable=False),
    sa.Column('confidence_label', sa.String(length=20), nullable=False),
    sa.Column('verification_status', sa.String(length=30), nullable=False),
    sa.Column('reentrancy_related', sa.Boolean(), nullable=False),
    sa.Column('program_counter', sa.Integer(), nullable=True),
    sa.Column('opcode_evidence', sa.JSON(), nullable=True),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vuln_category_severity', 'vulnerabilities', ['category', 'severity'], unique=False)
    op.create_index('ix_vuln_scan', 'vulnerabilities', ['scan_id'], unique=False)


def downgrade() -> None:
    # drop_table also removes the table's indexes. (MySQL refuses to drop an index that backs a foreign key.)
    op.drop_table('vulnerabilities')
    op.drop_table('scan_reports')
    op.drop_table('ai_analysis')
    op.drop_table('scans')
    op.drop_table('uploaded_files')
    op.drop_table('user_sessions')
    op.drop_table('usage_events')
    op.drop_table('projects')
    op.drop_table('audit_logs')
    op.drop_table('users')
