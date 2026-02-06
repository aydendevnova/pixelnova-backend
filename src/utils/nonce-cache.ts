interface NonceEntry {
  nonce: string;
  expiry: number;
}

class NonceCache {
  private cache: Map<string, NonceEntry> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor(cleanupIntervalMs: number = 60000) {
    // Default cleanup every minute
    this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
  }

  async cacheNonce(
    userId: string,
    nonce: string,
    ttlSeconds: number
  ): Promise<void> {
    const expiry = Date.now() + ttlSeconds * 1000;
    this.cache.set(`${userId}:${nonce}`, { nonce, expiry });
  }

  async verifyAndDeleteNonce(userId: string, nonce: string): Promise<boolean> {
    const key = `${userId}:${nonce}`;
    const entry = this.cache.get(key);

    if (!entry) return false;
    if (entry.expiry < Date.now()) {
      this.cache.delete(key);
      return false;
    }

    this.cache.delete(key);
    return true;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (entry.expiry < now) {
        this.cache.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.cache.clear();
  }
}

// Create a singleton instance
export const nonceCache = new NonceCache();

// Cleanup on process exit
process.on("SIGTERM", () => nonceCache.destroy());
process.on("SIGINT", () => nonceCache.destroy());
