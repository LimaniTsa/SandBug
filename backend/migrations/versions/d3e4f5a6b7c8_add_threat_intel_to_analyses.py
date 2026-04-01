"""add threat_intel to analyses

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-04-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'd3e4f5a6b7c8'
down_revision = 'c2d3e4f5a6b7'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('analyses', sa.Column('threat_intel', sa.JSON(), nullable=True))


def downgrade():
    op.drop_column('analyses', 'threat_intel')
