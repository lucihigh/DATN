export type Role = 'USER' | 'ADMIN';

export interface User {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
}

export interface Wallet {
  id: string;
  userId: string;
  balance: number;
  currency: string;
}

export interface LoginEvent {
  userId: string;
  ipAddress: string;
  userAgent?: string;
  timestamp: string;
}
