/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */

'use strict';

class API {

  async call({ method, path, body }) {
    const url = `/api${path}`;
    const res = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      body: body
        ? JSON.stringify(body)
        : undefined,
    });

    if (res.status === 204) {
      return undefined;
    }

    const json = await res.json();

    if (!res.ok) {
      throw new Error(json.error || res.statusText);
    }

    return json;
  }

  async getLang() {
    return this.call({
      method: 'get',
      path: '/lang',
    });
  }

  async getuiTrafficStats() {
    return this.call({
      method: 'get',
      path: '/ui-traffic-stats',
    });
  }

  async getChartType() {
    return this.call({
      method: 'get',
      path: '/ui-chart-type',
    });
  }

  async getSession() {
    return this.call({
      method: 'get',
      path: '/session',
    });
  }

  async createSession({ username, password }) {
    return this.call({
      method: 'post',
      path: '/session',
      body: { username, password },
    });
  }

  async deleteSession() {
    return this.call({
      method: 'delete',
      path: '/session',
    });
  }

  async getClients() {
    return this.call({
      method: 'get',
      path: '/wireguard/client',
    }).then((clients) => clients.map((client) => ({
      ...client,
      createdAt: client.createdAt ? new Date(client.createdAt) : null,
      updatedAt: client.updatedAt ? new Date(client.updatedAt) : null,
      expiresAt: client.expiresAt && !isNaN(new Date(client.expiresAt)) ? new Date(client.expiresAt) : null,
      latestHandshakeAt: client.latestHandshakeAt !== null && !isNaN(new Date(client.latestHandshakeAt))
        ? new Date(client.latestHandshakeAt)
        : null,
    })));
  }

  async createClient({ name, type, Jc, Jmin, Jmax, expiresAt }) {
    return this.call({
      method: 'post',
      path: '/wireguard/client',
      body: { name, type, Jc, Jmin, Jmax, expiresAt },
    });
  }

  async deleteClient({ clientId }) {
    return this.call({
      method: 'delete',
      path: `/wireguard/client/${clientId}`,
    });
  }

  async enableClient({ clientId }) {
    return this.call({
      method: 'post',
      path: `/wireguard/client/${clientId}/enable`,
    });
  }

  async disableClient({ clientId }) {
    return this.call({
      method: 'post',
      path: `/wireguard/client/${clientId}/disable`,
    });
  }

  async updateClientName({ clientId, name }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/name/`,
      body: { name },
    });
  }

  async updateClientAddress({ clientId, address }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/address/`,
      body: { address },
    });
  }

  async updateClientAmneziaParams({ clientId, Jc, Jmin, Jmax }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/amnezia-params`,
      body: { Jc, Jmin, Jmax },
    });
  }

  async updateClientExpiration({ clientId, expiresAt }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/expiration`,
      body: { expiresAt },
    });
  }

  async updateClientType({ clientId, type, Jc, Jmin, Jmax }) {
    return this.call({
      method: 'put',
      path: `/wireguard/client/${clientId}/type`,
      body: { type, Jc, Jmin, Jmax },
    });
  }

  async getClientTraffic({ clientId, yearMonth }) {
    return this.call({
      method: 'get',
      path: `/wireguard/client/${clientId}/traffic/${yearMonth}`,
    });
  }

  async restoreConfiguration(file) {
    return this.call({
      method: 'put',
      path: '/wireguard/restore',
      body: { file },
    });
  }

}
