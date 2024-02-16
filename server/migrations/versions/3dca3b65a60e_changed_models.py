"""changed models

Revision ID: 3dca3b65a60e
Revises: af2f73286be7
Create Date: 2024-02-16 16:00:40.303426

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3dca3b65a60e'
down_revision = 'af2f73286be7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('coupon',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=50), nullable=False),
    sa.Column('discount_percentage', sa.Float(), nullable=False),
    sa.Column('valid_from', sa.DateTime(), nullable=False),
    sa.Column('valid_to', sa.DateTime(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code')
    )
    op.create_table('review',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('rating', sa.Integer(), nullable=False),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['product_id'], ['product.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.add_column(sa.Column('shipping_cost', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('discount', sa.Float(), nullable=True))

    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.add_column(sa.Column('promotional_price', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('image_url', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('category', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('is_available', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('is_featured', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('is_on_promotion', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('average_rating', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('review_count', sa.Integer(), nullable=True))

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('discount', sa.Float(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('discount')

    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.drop_column('review_count')
        batch_op.drop_column('average_rating')
        batch_op.drop_column('is_on_promotion')
        batch_op.drop_column('is_featured')
        batch_op.drop_column('is_available')
        batch_op.drop_column('category')
        batch_op.drop_column('image_url')
        batch_op.drop_column('promotional_price')

    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.drop_column('discount')
        batch_op.drop_column('shipping_cost')

    op.drop_table('review')
    op.drop_table('coupon')
    # ### end Alembic commands ###