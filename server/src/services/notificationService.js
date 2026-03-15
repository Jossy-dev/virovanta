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
    if (!userId || !title || !detail || !type || !tone) {
      return null;
    }

    return this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        return null;
      }

      if (dedupeKey) {
        const existing = (state.notifications || []).find(
          (notification) => notification.userId === userId && notification.dedupeKey === dedupeKey
        );
        if (existing) {
          return existing;
        }
      }

      const notification = {
        id: `notification_${crypto.randomUUID()}`,
        userId,
        type,
        tone,
        title,
        detail,
        entityType,
        entityId,
        dedupeKey: dedupeKey || null,
        createdAt: new Date().toISOString(),
        readAt: null
      };

      state.notifications = state.notifications || [];
      state.notifications.unshift(notification);
      return notification;
    });
  }

  async listForUser(userId, limit = 20) {
    return this.store.read((state) => {
      const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
      const ownedNotifications = sortNotifications(
        (state.notifications || []).filter((notification) => notification.userId === userId)
      );

      return {
        notifications: ownedNotifications.slice(0, safeLimit).map(publicNotification),
        unreadCount: ownedNotifications.filter((notification) => !notification.readAt).length
      };
    });
  }

  async markRead(userId, ids = []) {
    return this.store.write((state) => {
      const requestedIds = new Set(
        Array.isArray(ids) ? ids.map((value) => String(value || "").trim()).filter(Boolean) : []
      );
      const readAll = requestedIds.size === 0;
      const readAt = new Date().toISOString();
      let updated = 0;

      for (const notification of state.notifications || []) {
        if (notification.userId !== userId || notification.readAt) {
          continue;
        }

        if (!readAll && !requestedIds.has(notification.id)) {
          continue;
        }

        notification.readAt = readAt;
        updated += 1;
      }

      return {
        updated
      };
    });
  }
}

export { publicNotification };
