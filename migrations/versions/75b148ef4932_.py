"""empty message

Revision ID: 75b148ef4932
Revises: 
Create Date: 2022-01-07 20:46:47.095426

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '75b148ef4932'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('approvals_needed', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_username'), 'user', ['username'], unique=True)
    op.create_table('credential',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('credential_id', sa.String(), nullable=False),
    sa.Column('signature_count', sa.Integer(), nullable=True),
    sa.Column('websafe_credential', sa.String(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_credential_credential_id'), 'credential', ['credential_id'], unique=True)
    op.create_table('re_pass_recovery_credential',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('credential_id', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('date_added', sa.DateTime(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_re_pass_recovery_credential_credential_id'), 're_pass_recovery_credential', ['credential_id'], unique=False)
    op.create_table('re_pass_recovery_request',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('recovered_credential_id', sa.String(), nullable=False),
    sa.Column('recovered_websafe_credential', sa.String(), nullable=False),
    sa.Column('created', sa.DateTime(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('approvals_needed', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_re_pass_recovery_request_recovered_credential_id'), 're_pass_recovery_request', ['recovered_credential_id'], unique=True)
    op.create_table('re_pass_recovery_approval',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('recovery_request_id', sa.Integer(), nullable=False),
    sa.Column('approving_credential_id', sa.Integer(), nullable=False),
    sa.Column('challenge', sa.String(), nullable=False),
    sa.Column('attestation', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['approving_credential_id'], ['re_pass_recovery_credential.id'], ),
    sa.ForeignKeyConstraint(['recovery_request_id'], ['re_pass_recovery_request.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('re_pass_recovery_approval')
    op.drop_index(op.f('ix_re_pass_recovery_request_recovered_credential_id'), table_name='re_pass_recovery_request')
    op.drop_table('re_pass_recovery_request')
    op.drop_index(op.f('ix_re_pass_recovery_credential_credential_id'), table_name='re_pass_recovery_credential')
    op.drop_table('re_pass_recovery_credential')
    op.drop_index(op.f('ix_credential_credential_id'), table_name='credential')
    op.drop_table('credential')
    op.drop_index(op.f('ix_user_username'), table_name='user')
    op.drop_table('user')
    # ### end Alembic commands ###
