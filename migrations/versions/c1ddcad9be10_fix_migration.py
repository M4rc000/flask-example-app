"""fix migration

Revision ID: c1ddcad9be10
Revises: 5c96c1bf7f2c
Create Date: 2025-05-20 00:38:02.756958

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'c1ddcad9be10'
down_revision = '5c96c1bf7f2c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('movies_now_showing', schema=None) as batch_op:
        batch_op.drop_column('year')
        batch_op.drop_column('type')
        batch_op.drop_column('name')
        batch_op.drop_column('duration')
        batch_op.drop_column('rating')
        batch_op.drop_column('picture')
        batch_op.drop_column('is_active')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('movies_now_showing', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_active', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('picture', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('rating', mysql.VARCHAR(length=10), nullable=False))
        batch_op.add_column(sa.Column('duration', mysql.VARCHAR(length=30), nullable=False))
        batch_op.add_column(sa.Column('name', mysql.VARCHAR(length=50), nullable=False))
        batch_op.add_column(sa.Column('type', mysql.VARCHAR(length=30), nullable=False))
        batch_op.add_column(sa.Column('year', mysql.VARCHAR(length=10), nullable=False))

    # ### end Alembic commands ###
