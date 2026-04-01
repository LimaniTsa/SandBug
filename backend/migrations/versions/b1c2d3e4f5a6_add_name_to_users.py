"""add name to users

Revision ID: b1c2d3e4f5a6
Revises: a94beb710515
Create Date: 2026-04-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'b1c2d3e4f5a6'
down_revision = 'a94beb710515'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('name', sa.String(length=100), nullable=True))


def downgrade():
    op.drop_column('users', 'name')
