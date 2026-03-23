import crypto from "crypto";

function publicNotification(notification) {
  return {
    id: notification.id,
    type: notification.type,
    tone: notification.tone,
    title: notification.title,
    detail: notification.detail,
    entityType: notification.entityType || null,
    entityId: notification.entityId || null,
    createdAt: notification.createdAt,
    readAt: notification.readAt || null
  };
}

function sortNotifications(notifications) {
  return [...notifications].sort((left, right) => {
    return new Date(right.createdAt || 0).getTime() - new Date(left.createdAt || 0).getTime();
  });
}

export class NotificationService {
  constructor({ store, logger }) {
    this.store = store;
    this.logger = logger;
  }

  async create({
    userId,
    type,
    tone,
    title,
    detail,
    entityType = null,
    entityId = null,
    dedupeKey = ""
  }) {
    return this.store.createNotification({
      userId,
      type,
      tone,
      title,
      detail,
      entityType,
      entityId,
      dedupeKey,
      createdAt: new Date().toISOString()
    });
  }

  async listForUser(userId, limit = 20, offset = 0) {
    const result = await this.store.listNotificationsForUser(userId, limit, offset);
    return {
      ...result,
      notifications: (result.notifications || []).map(publicNotification)
    };
  }

  async markRead(userId, ids = []) {
    return this.store.markNotificationsRead(userId, ids);
  }
}

export { publicNotification };
