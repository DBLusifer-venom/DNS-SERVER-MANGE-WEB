<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const servers = ref([])
const error = ref('')
const testing = ref(null)
const form = ref({
  name: '',
  host: '',
  notes: '',
  rndc_port: 953,
  rndc_key_name: 'rndc-key',
  rndc_algorithm: 'sha256',
  rndc_secret: '',
  update_port: 53,
  update_key_name: 'update-key',
  update_secret: '',
})

const isAdmin = () => auth.user?.role === 'admin'

async function load() {
  const res = await api.get('/api/servers')
  servers.value = res.data
}

async function create() {
  error.value = ''
  try {
    await api.post('/api/servers', form.value)
    form.value = {
      name: '', host: '', notes: '',
      rndc_port: 953, rndc_key_name: 'rndc-key', rndc_algorithm: 'sha256', rndc_secret: '',
      update_port: 53, update_key_name: 'update-key', update_secret: '',
    }
    await load()
  } catch (e) {
    error.value = e.response?.data?.detail || 'Failed to create server'
  }
}

async function testServer(s) {
  testing.value = s.id
  try {
    const res = await api.post(`/api/servers/${s.id}/test`)
    s.status = res.data.ok ? 'ok' : 'error'
    s.version = res.data.version
    s.last_error = res.data.ok ? null : res.data.detail
  } finally {
    testing.value = null
  }
}

async function remove(s) {
  if (!confirm(`Delete server ${s.name}?`)) return
  await api.delete(`/api/servers/${s.id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <h1>DNS Servers</h1>

    <form v-if="isAdmin()" class="panel mt" @submit.prevent="create">
      <h3>Register server</h3>
      <div class="grid">
        <div>
          <label>Name</label>
          <input v-model="form.name" required minlength="2" placeholder="ns1" />
        </div>
        <div>
          <label>Host (IP or FQDN)</label>
          <input v-model="form.host" required placeholder="10.0.0.10" />
        </div>
        <div>
          <label>Notes</label>
          <input v-model="form.notes" placeholder="optional" />
        </div>
      </div>
      <h4>rndc control (port {{ form.rndc_port }})</h4>
      <div class="grid">
        <div>
          <label>Key name</label>
          <input v-model="form.rndc_key_name" required />
        </div>
        <div>
          <label>Algorithm</label>
          <select v-model="form.rndc_algorithm">
            <option value="sha256">hmac-sha256</option>
            <option value="sha512">hmac-sha512</option>
            <option value="sha1">hmac-sha1</option>
            <option value="md5">hmac-md5</option>
          </select>
        </div>
        <div>
          <label>Secret (base64, from tsig-keygen)</label>
          <input v-model="form.rndc_secret" required placeholder="base64 secret" />
        </div>
      </div>
      <h4>Dynamic update (RFC 2136, port {{ form.update_port }})</h4>
      <div class="grid">
        <div>
          <label>Key name</label>
          <input v-model="form.update_key_name" required />
        </div>
        <div>
          <label>Secret (base64)</label>
          <input v-model="form.update_secret" required placeholder="base64 secret" />
        </div>
      </div>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary mt" type="submit">Register server</button>
    </form>

    <div class="panel mt">
      <table>
        <thead>
          <tr><th>Name</th><th>Host</th><th>Status</th><th>BIND version</th><th>Checked</th><th>Actions</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in servers" :key="s.id">
            <td>{{ s.name }}</td>
            <td class="muted">{{ s.host }}:{{ s.rndc_port }}</td>
            <td>
              <span class="badge" :class="s.status === 'ok' ? 'operator' : s.status === 'error' ? 'danger' : ''">
                {{ s.status }}
              </span>
              <div v-if="s.last_error" class="small error">{{ s.last_error }}</div>
            </td>
            <td class="muted small">{{ s.version || '—' }}</td>
            <td class="muted small">{{ s.last_checked_at ? new Date(s.last_checked_at).toLocaleString() : '—' }}</td>
            <td class="row">
              <button :disabled="testing === s.id" @click="testServer(s)">{{ testing === s.id ? 'Testing…' : 'Test' }}</button>
              <button v-if="isAdmin()" class="danger" @click="remove(s)">Delete</button>
            </td>
          </tr>
          <tr v-if="!servers.length">
            <td colspan="6" class="muted">No servers registered yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 0 1rem;
}

h4 {
  margin: 1rem 0 0;
  color: var(--accent);
  font-weight: 500;
  font-size: 0.9rem;
}
</style>