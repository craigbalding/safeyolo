import { atom, computed } from 'nanostores'

// ^ Core state atoms
type User = {
  name: string
  id: number
}

type Theme = 'light' | 'dark' | 'system'

// ^ Individual atoms for granular state management
export const $counter = atom(0)
export const $user = atom<User | null>(null)
export const $theme = atom<Theme>('system')

// ^ Computed derived state
export const $isLoggedIn = computed($user, (user) => user !== null)
export const $displayName = computed($user, (user) => user?.name ?? 'Guest')
export const $counterSquared = computed($counter, (count) => count * count)

// ^ Actions to modify state
export function incrementCounter(): void {
  $counter.set($counter.get() + 1)
}

export function decrementCounter(): void {
  $counter.set($counter.get() - 1)
}

export function resetCounter(): void {
  $counter.set(0)
}

export function setUser(name: string, id: number): void {
  $user.set({ name, id })
}

export function clearUser(): void {
  $user.set(null)
}

export function cycleTheme(): void {
  const themes: Theme[] = ['light', 'dark', 'system']
  const current = $theme.get()
  const nextIndex = (themes.indexOf(current) + 1) % themes.length
  $theme.set(themes[nextIndex])
}
