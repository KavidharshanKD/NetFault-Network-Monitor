"""
In-memory Mock Supabase Client for offline unit and integration tests.
Implements the Supabase query builder interface (.table().select().eq().insert().update().delete().execute())
and Supabase Auth client interface (.auth.sign_in_with_password(), .auth.sign_up(), .auth.sign_out(), .auth.reset_password_for_email())
with thread safety, UUID generation, foreign-key cascades, and multi-tenant user filtering.
"""

import uuid
import copy
from datetime import datetime, timezone

try:
    from supabase import AuthApiError
except Exception:
    class AuthApiError(Exception):
        def __init__(self, message, status=400):
            super().__init__(message)
            self.message = message
            self.status = status

class MockUser:
    def __init__(self, user_id, email, user_metadata=None):
        self.id = user_id
        self.email = email
        self.user_metadata = user_metadata or {}
        self.confirmed_at = datetime.now(timezone.utc).isoformat()

class MockSession:
    def __init__(self, user, access_token=None):
        self.user = user
        self.access_token = access_token or f"mock-token-{uuid.uuid4()}"
        self.refresh_token = f"mock-refresh-{uuid.uuid4()}"

class MockAuthResponse:
    def __init__(self, user=None, session=None):
        self.user = user
        self.session = session

class MockAuth:
    """Mock implementation of Supabase GoTrue Auth client."""
    def __init__(self, client):
        self.client = client
        # Seed default admin user
        admin_id = "00000000-0000-0000-0000-000000000001"
        self._users = {
            "admin@supabase.local": {
                "id": admin_id,
                "email": "admin@supabase.local",
                "password": "admin123",
                "metadata": {"full_name": "Network Administrator"}
            }
        }
        self.current_session = None

    def sign_in_with_password(self, credentials):
        email = credentials.get("email", "").strip().lower()
        password = credentials.get("password", "")

        user_record = self._users.get(email)
        if not user_record or user_record["password"] != password:
            raise AuthApiError("Invalid login credentials", 400, "invalid_credentials")

        user = MockUser(user_record["id"], user_record["email"], user_record["metadata"])
        session = MockSession(user)
        self.current_session = session
        return MockAuthResponse(user=user, session=session)

    def sign_up(self, credentials):
        email = credentials.get("email", "").strip().lower()
        password = credentials.get("password", "")
        options = credentials.get("options", {})
        metadata = options.get("data", {}) if options else {}

        if email in self._users:
            raise AuthApiError("User already registered", 422, "user_already_exists")

        user_id = str(uuid.uuid4())
        self._users[email] = {
            "id": user_id,
            "email": email,
            "password": password,
            "metadata": metadata
        }

        user = MockUser(user_id, email, metadata)
        session = MockSession(user)
        self.current_session = session
        return MockAuthResponse(user=user, session=session)

    def sign_out(self):
        self.current_session = None
        return True

    def reset_password_for_email(self, email, options=None):
        return True

    def get_user(self, jwt=None):
        if self.current_session:
            return self.current_session.user
        return None

class MockExecuteResult:
    def __init__(self, data=None, count=None):
        self.data = data if data is not None else []
        self.count = count if count is not None else len(self.data)

class MockQueryBuilder:
    def __init__(self, table_name, storage):
        self.table_name = table_name
        self.storage = storage
        self.op = 'select'
        self.payload = None
        self.filters = []
        self.order_col = None
        self.order_desc = False
        self.limit_val = None
        self.range_val = None
        self.count_mode = None
        self.on_conflict = None

    def select(self, columns='*', count=None):
        self.op = 'select'
        self.count_mode = count
        return self

    def insert(self, payload):
        self.op = 'insert'
        self.payload = payload
        return self

    def update(self, payload):
        self.op = 'update'
        self.payload = payload
        return self

    def delete(self):
        self.op = 'delete'
        return self

    def upsert(self, payload, on_conflict=None):
        self.op = 'upsert'
        self.payload = payload
        self.on_conflict = on_conflict
        return self

    def eq(self, column, value):
        self.filters.append(('eq', column, value))
        return self

    def neq(self, column, value):
        self.filters.append(('neq', column, value))
        return self

    def in_(self, column, values):
        self.filters.append(('in', column, values))
        return self

    def is_(self, column, value):
        self.filters.append(('is', column, value))
        return self

    def or_(self, expr):
        self.filters.append(('or', expr))
        return self

    def gte(self, column, value):
        self.filters.append(('gte', column, value))
        return self

    def lte(self, column, value):
        self.filters.append(('lte', column, value))
        return self

    def order(self, column, desc=False):
        self.order_col = column
        self.order_desc = desc
        return self

    def limit(self, count):
        self.limit_val = count
        return self

    def range(self, start, end):
        self.range_val = (start, end)
        return self

    def _matches(self, row):
        for f in self.filters:
            if f[0] == 'eq':
                _, col, val = f
                if str(row.get(col)) != str(val):
                    return False
            elif f[0] == 'neq':
                _, col, val = f
                if str(row.get(col)) == str(val):
                    return False
            elif f[0] == 'in':
                _, col, vals = f
                val_strs = {str(v) for v in vals}
                if str(row.get(col)) not in val_strs and row.get(col) not in vals:
                    return False
            elif f[0] == 'is':
                _, col, val = f
                target = None if val in ('null', None) else val
                if row.get(col) is not target and (target is None and row.get(col) != ''):
                    return False
            elif f[0] == 'gte':
                _, col, val = f
                if (row.get(col) or '') < str(val):
                    return False
            elif f[0] == 'lte':
                _, col, val = f
                if (row.get(col) or '') > str(val):
                    return False
            elif f[0] == 'or':
                expr = f[1]
                parts = expr.split(',')
                matched_any = False
                for p in parts:
                    if '.ilike.' in p:
                        col, pattern = p.split('.ilike.')
                        pat_clean = pattern.replace('%', '').lower()
                        if pat_clean in str(row.get(col, '')).lower():
                            matched_any = True
                            break
                    elif '.eq.' in p:
                        col, val = p.split('.eq.')
                        if str(row.get(col)) == str(val):
                            matched_any = True
                            break
                    elif '.is.null' in p:
                        col = p.split('.is.null')[0]
                        if row.get(col) is None or str(row.get(col)).lower() == 'none':
                            matched_any = True
                            break
                if not matched_any:
                    return False
        return True

    def execute(self):
        if self.table_name == 'devices_with_status':
            target_rows = self.storage.get_devices_with_status()
        elif self.table_name == 'monitoring_history_with_devices':
            target_rows = self.storage.get_monitoring_history_with_devices()
        else:
            target_rows = self.storage.tables.setdefault(self.table_name, [])

        if self.op == 'select':
            matched = [copy.deepcopy(r) for r in target_rows if self._matches(r)]
            total_count = len(matched)

            if self.order_col:
                matched.sort(
                    key=lambda r: (r.get(self.order_col) is None, r.get(self.order_col) or ''),
                    reverse=self.order_desc
                )

            if self.range_val is not None:
                start, end = self.range_val
                matched = matched[start:end + 1]
            elif self.limit_val is not None:
                matched = matched[:self.limit_val]

            return MockExecuteResult(data=matched, count=total_count if self.count_mode else len(matched))

        elif self.op == 'insert':
            items = self.payload if isinstance(self.payload, list) else [self.payload]
            inserted = []
            for item in items:
                row = copy.deepcopy(item)
                if 'id' not in row or not row['id']:
                    row['id'] = str(uuid.uuid4())
                if 'created_at' not in row:
                    row['created_at'] = datetime.now(timezone.utc).isoformat()
                if 'updated_at' not in row:
                    row['updated_at'] = datetime.now(timezone.utc).isoformat()
                target_rows.append(row)
                inserted.append(copy.deepcopy(row))
            return MockExecuteResult(data=inserted)

        elif self.op == 'update':
            updated = []
            for r in target_rows:
                if self._matches(r):
                    r.update(copy.deepcopy(self.payload))
                    r['updated_at'] = datetime.now(timezone.utc).isoformat()
                    updated.append(copy.deepcopy(r))
            return MockExecuteResult(data=updated)

        elif self.op == 'delete':
            remaining = []
            deleted = []
            for r in target_rows:
                if self._matches(r):
                    deleted.append(r)
                else:
                    remaining.append(r)
            self.storage.tables[self.table_name] = remaining

            if self.table_name == 'devices':
                deleted_ids = {d['id'] for d in deleted}
                if 'monitoring_history' in self.storage.tables:
                    self.storage.tables['monitoring_history'] = [
                        h for h in self.storage.tables['monitoring_history']
                        if h.get('device_id') not in deleted_ids
                    ]
                if 'traceroute_history' in self.storage.tables:
                    self.storage.tables['traceroute_history'] = [
                        t for t in self.storage.tables['traceroute_history']
                        if t.get('device_id') not in deleted_ids
                    ]

            return MockExecuteResult(data=deleted)

        elif self.op == 'upsert':
            item = copy.deepcopy(self.payload)
            conflict_col = self.on_conflict or 'id'
            conflict_val = item.get(conflict_col)

            found = False
            for r in target_rows:
                if str(r.get(conflict_col)) == str(conflict_val):
                    r.update(item)
                    r['updated_at'] = datetime.now(timezone.utc).isoformat()
                    found = True
                    break
            if not found:
                if 'id' not in item or not item['id']:
                    item['id'] = str(uuid.uuid4())
                if 'created_at' not in item:
                    item['created_at'] = datetime.now(timezone.utc).isoformat()
                target_rows.append(item)
            return MockExecuteResult(data=[item])

        return MockExecuteResult()

class MockSupabaseClient:
    """Mock Supabase client holding isolated in-memory tables and Supabase Auth client."""
    def __init__(self):
        self.tables = {
            'devices': [],
            'monitoring_history': [],
            'application_settings': [],
            'traceroute_history': [],
            'users': [],
            'incidents': [],
            'notification_history': []
        }
        self.auth = MockAuth(self)

    def table(self, table_name):
        return MockQueryBuilder(table_name, self)

    def get_devices_with_status(self):
        devices = self.tables.get('devices', [])
        history = self.tables.get('monitoring_history', [])
        result = []
        for d in devices:
            row = copy.deepcopy(d)
            dev_hists = [h for h in history if str(h.get('device_id')) == str(d['id'])]
            if dev_hists:
                dev_hists.sort(key=lambda h: h.get('checked_at', ''), reverse=True)
                latest = dev_hists[0]
                row['overall_status'] = latest.get('overall_status')
                row['reachability_status'] = latest.get('reachability_status')
                row['service_status'] = latest.get('service_status')
                row['response_time_ms'] = latest.get('response_time_ms')
                row['packets_sent'] = latest.get('packets_sent')
                row['packets_received'] = latest.get('packets_received')
                row['packets_lost'] = latest.get('packets_lost')
                row['packet_loss_pct'] = latest.get('packet_loss_pct')
                row['min_rtt_ms'] = latest.get('min_rtt_ms')
                row['max_rtt_ms'] = latest.get('max_rtt_ms')
                row['avg_rtt_ms'] = latest.get('avg_rtt_ms')
                row['packet_loss_status'] = latest.get('packet_loss_status')
                row['fault_category'] = latest.get('fault_category')
                row['fault_details'] = latest.get('fault_details')
                row['last_checked'] = latest.get('checked_at')
            else:
                row['overall_status'] = None
                row['reachability_status'] = None
                row['service_status'] = None
                row['response_time_ms'] = None
                row['packets_sent'] = None
                row['packets_received'] = None
                row['packets_lost'] = None
                row['packet_loss_pct'] = None
                row['min_rtt_ms'] = None
                row['max_rtt_ms'] = None
                row['avg_rtt_ms'] = None
                row['packet_loss_status'] = None
                row['fault_category'] = None
                row['fault_details'] = None
                row['last_checked'] = None
            result.append(row)
        return result

    def get_monitoring_history_with_devices(self):
        devices_map = {str(d['id']): d for d in self.tables.get('devices', [])}
        history = self.tables.get('monitoring_history', [])
        result = []
        for h in history:
            row = copy.deepcopy(h)
            d = devices_map.get(str(h.get('device_id')), {})
            row['user_id'] = d.get('user_id')
            row['device_name'] = d.get('device_name', 'Unknown')
            row['ip_address'] = d.get('ip_address', 'N/A')
            row['port'] = d.get('port')
            result.append(row)
        return result

    def get_incidents_with_devices(self):
        devices_map = {str(d['id']): d for d in self.tables.get('devices', [])}
        incidents = self.tables.get('incidents', [])
        result = []
        for inc in incidents:
            row = copy.deepcopy(inc)
            d = devices_map.get(str(inc.get('device_id')), {})
            row['device_name'] = d.get('device_name', 'Unknown')
            row['ip_address'] = d.get('ip_address', 'N/A')
            row['port'] = d.get('port')
            result.append(row)
        return result

