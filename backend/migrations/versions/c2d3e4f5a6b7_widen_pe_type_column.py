"""widen pe_type column

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-04-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'c2d3e4f5a6b7'
down_revision = 'b1c2d3e4f5a6'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('static_results', 'pe_type',
                    existing_type=sa.String(50),
                    type_=sa.String(500),
                    existing_nullable=True)


def downgrade():
    op.alter_column('static_results', 'pe_type',
                    existing_type=sa.String(500),
                    type_=sa.String(50),
                    existing_nullable=True)
