"""
iSCSI Target authorized networks

Revision ID: 34df1ca8a04e
Revises: afa3965ed8fc
Create Date: 2022-06-12 17:50:03.593598+00:00

"""
import json
import sqlalchemy as sa

from alembic import op


revision = '34df1ca8a04e'
down_revision = 'afa3965ed8fc'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('services_iscsitarget', schema=None) as batch_op:
        batch_op.add_column(sa.Column('iscsi_target_auth_networks', sa.TEXT(), nullable=False, server_default='[]'))

    conn = op.get_bind()

    target_groups = [dict(row) for row in conn.execute("SELECT * FROM services_iscsitargetgroups").fetchall()]
    for target_group in target_groups:
        initiator = dict(conn.execute(
            "SELECT * FROM services_iscsitargetauthorizedinitiator WHERE id = ?",
            [target_group['iscsi_target_initiatorgroup_id']]
        ).first())


        auth_network = initiator['iscsi_target_initiator_auth_network']

        conn.execute("UPDATE services_iscsitarget SET iscsi_target_auth_networks = ? WHERE id = ?", (
            json.dumps([] if auth_network == 'ALL' else auth_network.split()),
            target_group['iscsi_target_id']
        ))

    with op.batch_alter_table('services_iscsitargetauthorizedinitiator', schema=None) as batch_op:
        batch_op.drop_column('iscsi_target_initiator_auth_network')


def downgrade():
    pass
