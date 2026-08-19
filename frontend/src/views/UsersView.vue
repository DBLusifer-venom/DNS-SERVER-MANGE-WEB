<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'

const users = ref([])
const error = ref('')
const form = ref({ username: '', email: '', password: '', role: 'viewer' })

async function load() {
  const res = await api.get('/api/users')
  users.value = res.data
}

async function create() {
  error.value = ''
  try {
    await api.post('/api/users', form.value)
    form.value = { username: '', email: '', password: '', role: 'viewer' }
    await load()
  } catch (e) {
    error.value = e.response?.data?.detail || 'Failed to create user'
  }
}

async function toggleActive(u) {
  await api.patch(`/api/users/${u.id}`, { active: !u.active })
  await load()
}

async function setRole(u, role) {
  await api.patch(`/api/users/${u.id}`, { role })
  await load()
}

async function remove(u) {
  if (!confirm(`Delete user ${u.username}?`)) return
  await api.delete(`/api/users/${u.id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <h1>Users</h1>

    <form class="panel mt" @submit.prevent="create">
      <h3>Create user</h3>
      <div class="grid">
        <div>
          <label>Username</label>
          <input v-model="form.username" required minlength="3" />
        </div>
        <div>
          <label>Email</label>
          <input v-model="form.email" type="email" required />
        </div>
        <div>
          <label>Password</label>
          <input v-model="form.password" type="password" required minlength="10" />
        </div>
        <div>
          <label>Role</label>
          <select v-model="form.role">
            <option value="admin">admin</option>
            <option value="operator">operator</option>
            <option value="viewer">viewer</option>
          </select>
        </div>
      </div>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary mt" type="submit">Create user</button>
    </form>

    <div class="panel mt">
      <table>
        <thead>
          <tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td>{{ u.username }}</td>
            <td class="muted">{{ u.email }}</td>
            <td>
              <select :value="u.role" @change="setRole(u, $event.target.value)">
                <option value="admin">admin</option>
                <option value="operator">operator</option>
                <option value="viewer">viewer</option>
              </select>
            </td>
            <td>
              <span class="badge" :class="u.active ? 'operator' : ''">{{ u.active ? 'active' : 'disabled' }}</span>
            </td>
            <td class="row">
              <button @click="toggleActive(u)">{{ u.active ? 'Disable' : 'Enable' }}</button>
              <button class="danger" @click="remove(u)">Delete</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 0 1rem;
}
</style>