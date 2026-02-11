import { css, html, LitElement } from 'lit'
import { customElement } from 'lit/decorators.js'
import { withStores } from '@nanostores/lit'
import '@patternfly/elements/pf-card/pf-card.js'
import '@patternfly/elements/pf-button/pf-button.js'
import '@patternfly/elements/pf-badge/pf-badge.js'
import '@patternfly/elements/pf-switch/pf-switch.js'

import {
  $counter,
  $counterSquared,
  $displayName,
  $isLoggedIn,
  $theme,
  $user,
  clearUser,
  cycleTheme,
  decrementCounter,
  incrementCounter,
  resetCounter,
  setUser,
} from './pieces/store.js'

/**
 * StateDemo element - demonstrates nanostores state management
 *
 * Uses @nanostores/lit for reactive store bindings
 */
@customElement('state-demo')
export class StateDemo extends withStores(LitElement, [
  $counter,
  $counterSquared,
  $displayName,
  $isLoggedIn,
  $theme,
  $user,
]) {
  private handleIncrement(): void {
    incrementCounter()
  }

  private handleDecrement(): void {
    decrementCounter()
  }

  private handleReset(): void {
    resetCounter()
  }

  private handleLogin(): void {
    const names = ['Alice', 'Bob', 'Charlie', 'Diana']
    const randomName = names[Math.floor(Math.random() * names.length)]
    const randomId = Math.floor(Math.random() * 10000)
    setUser(randomName, randomId)
  }

  private handleLogout(): void {
    clearUser()
  }

  private handleThemeCycle(): void {
    cycleTheme()
  }

  render() {
    const counter = $counter.get()
    const counterSquared = $counterSquared.get()
    const displayName = $displayName.get()
    const isLoggedIn = $isLoggedIn.get()
    const theme = $theme.get()
    const user = $user.get()

    return html`
      <div class="container">
        <h2>Nanostores State Management Demo</h2>

        <pf-card class="demo-card">
          <h3 slot="header">
            Counter State
            <pf-badge>${counter}</pf-badge>
          </h3>
          <div class="counter-section">
            <div class="stat-row">
              <span>Current Value:</span>
              <code>${counter}</code>
            </div>
            <div class="stat-row">
              <span>Squared (computed):</span>
              <code>${counterSquared}</code>
            </div>
            <div class="button-row">
              <pf-button variant="primary" @click="${this.handleDecrement}">
                - Decrement
              </pf-button>
              <pf-button variant="secondary" @click="${this.handleReset}">
                Reset
              </pf-button>
              <pf-button variant="primary" @click="${this.handleIncrement}">
                Increment +
              </pf-button>
            </div>
          </div>
        </pf-card>

        <pf-card class="demo-card">
          <h3 slot="header">
            User State
            <pf-badge state="${isLoggedIn ? 'green' : 'grey'}">
              ${isLoggedIn ? 'Logged In' : 'Guest'}
            </pf-badge>
          </h3>
          <div class="user-section">
            <div class="stat-row">
              <span>Display Name (computed):</span>
              <code>${displayName}</code>
            </div>
            ${user
              ? html`
                <div class="stat-row">
                  <span>User ID:</span>
                  <code>${user.id}</code>
                </div>
              `
              : null}
            <div class="button-row">
              ${isLoggedIn
                ? html`
                  <pf-button variant="danger" @click="${this.handleLogout}">
                    Logout
                  </pf-button>
                `
                : html`
                  <pf-button variant="primary" @click="${this.handleLogin}">
                    Random Login
                  </pf-button>
                `}
            </div>
          </div>
        </pf-card>

        <pf-card class="demo-card">
          <h3 slot="header">
            Theme State
            <pf-badge state="${`theme-${theme}`}">${theme}</pf-badge>
          </h3>
          <div class="theme-section">
            <div class="stat-row">
              <span>Current Theme:</span>
              <code>${theme}</code>
            </div>
            <div class="button-row">
              <pf-button variant="secondary" @click="${this.handleThemeCycle}">
                Cycle Theme (light → dark → system)
              </pf-button>
            </div>
          </div>
        </pf-card>

        <div class="info-section">
          <p>
            <strong>Note:</strong> All state is shared across components using nanostores. Try adding multiple
            <code>&lt;state-demo&gt;</code>
            elements - they will stay in sync!
          </p>
        </div>
      </div>
    `
  }

  static styles = css`
    :host {
      display: block;
      max-width: 800px;
      margin: 0 auto;
      padding: 1rem;
    }

    .container {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    h2 {
      text-align: center;
      margin: 0 0 0.5rem 0;
      font-size: 1.5rem;
    }

    h3 {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin: 0;
      font-size: 1.1rem;
    }

    .demo-card {
      --pf-c-card--BoxShadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    .counter-section,
    .user-section,
    .theme-section {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .stat-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.5rem;
      background: var(--pf-global--BackgroundColor--150, #f5f5f5);
      border-radius: 4px;
    }

    .stat-row span {
      font-size: 0.9rem;
      color: var(--pf-global--Color--200, #6c757d);
    }

    code {
      font-family: var(--pf-global--FontFamily--monospace, monospace);
      font-size: 0.9rem;
      background: var(--pf-global--BackgroundColor--100, #fff);
      padding: 0.25rem 0.5rem;
      border-radius: 3px;
      color: var(--pf-global--primary-color--100, #0066cc);
    }

    .button-row {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-top: 0.5rem;
    }

    .info-section {
      padding: 1rem;
      background: var(--pf-global--palette--blue-50, #e7f1fa);
      border-left: 4px solid var(--pf-global--primary-color--100, #0066cc);
      border-radius: 0 4px 4px 0;
    }

    .info-section p {
      margin: 0;
      font-size: 0.9rem;
      line-height: 1.5;
    }

    .info-section code {
      background: rgba(0, 0, 0, 0.05);
      padding: 0.125rem 0.25rem;
    }
  `
}

declare global {
  interface HTMLElementTagNameMap {
    'state-demo': StateDemo
  }
}
