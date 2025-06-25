import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ManagementClient } from 'auth0';
import { auth } from '@/lib/auth';

// Mock test data
const testUsers = [
  {
    "email": "alice@example.com",
    "email_verified": true,
    "given_name": "Alice",
    "family_name": "Wonderland",
    "name": "Alice Wonderland",
    "nickname": "alice",
    "user_id": "auth0|alice123",
    "created_at": "2024-01-01T12:00:00.000Z",
    "updated_at": "2025-01-01T12:00:00.000Z",
    "app_metadata": {
      "plan": "pro",
      "signup_source": "web"
    },
    "user_metadata": {
      "locale": "en-US"
    },
    "custom_password_hash": {
      "algorithm": "bcrypt",
      "hash": {
        "value": "$2b$10$w4kfaZVjrcQ6ZOMiG.M8JeNvnVQkPKZV03pbDUHbxy9Ug0h/McDXi"
      }
    }
  },
  {
    "email": "bob@example.com",
    "email_verified": false,
    "given_name": "Bob",
    "family_name": "Builder",
    "name": "Bob Builder",
    "nickname": "bobby",
    "user_id": "auth0|bob456",
    "created_at": "2024-02-01T10:00:00.000Z",
    "updated_at": "2025-02-01T10:00:00.000Z",
    "app_metadata": {
      "plan": "basic",
      "signup_source": "mobile"
    },
    "user_metadata": {
      "locale": "en-GB"
    },
    "password_hash": "$2b$10$w4kfaZVjrcQ6ZOMiG.M8JeNvnVQkPKZV03pbDUHbxy9Ug0h/McDXi"
  }
];

// Mock Auth0 Management Client
vi.mock('auth0', () => ({
  ManagementClient: vi.fn().mockImplementation(() => ({
    users: {
      getAll: vi.fn().mockResolvedValue({
        data: {
          users: testUsers
        }
      })
    }
  }))
}));

// Mock Better Auth adapter
const mockAdapter = {
  create: vi.fn().mockImplementation(async ({ model, data }) => {
    if (model === 'user') {
      return { id: data.email };
    }
    return data;
  }),
  findOne: vi.fn()
};

// Mock Better Auth context
const mockCtx = {
  adapter: mockAdapter,
  options: {
    plugins: [
      { id: 'admin' },
      { id: 'username' }
    ]
  }
};

describe('Auth0 Migration Script', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should correctly migrate users with custom password hashes', async () => {
    const { migrateFromAuth0 } = await import('./migrate-auth0');
    await migrateFromAuth0();

    // Verify that the adapter.create was called for each user
    expect(mockAdapter.create).toHaveBeenCalledTimes(2);

    // Verify Alice's data
    expect(mockAdapter.create).toHaveBeenCalledWith(expect.objectContaining({
      model: 'user',
      data: expect.objectContaining({
        email: 'alice@example.com',
        emailVerified: true,
        name: 'Alice Wonderland',
        username: 'alice',
        password: '$2b$10$w4kfaZVjrcQ6ZOMiG.M8JeNvnVQkPKZV03pbDUHbxy9Ug0h/McDXi'
      })
    }));

    // Verify Bob's data
    expect(mockAdapter.create).toHaveBeenCalledWith(expect.objectContaining({
      model: 'user',
      data: expect.objectContaining({
        email: 'bob@example.com',
        emailVerified: false,
        name: 'Bob Builder',
        username: 'bobby',
        password: '$2b$10$w4kfaZVjrcQ6ZOMiG.M8JeNvnVQkPKZV03pbDUHbxy9Ug0h/McDXi'
      })
    }));
  });

  it('should handle metadata correctly', async () => {
    const { migrateFromAuth0 } = await import('./migrate-auth0');
    await migrateFromAuth0();

    // Verify metadata handling for Alice
    expect(mockAdapter.create).toHaveBeenCalledWith(expect.objectContaining({
      model: 'user',
      data: expect.objectContaining({
        email: 'alice@example.com',
        metadata: {
          app: {
            plan: 'pro',
            signup_source: 'web'
          },
          user: {
            locale: 'en-US'
          }
        }
      })
    }));

    // Verify metadata handling for Bob
    expect(mockAdapter.create).toHaveBeenCalledWith(expect.objectContaining({
      model: 'user',
      data: expect.objectContaining({
        email: 'bob@example.com',
        metadata: {
          app: {
            plan: 'basic',
            signup_source: 'mobile'
          },
          user: {
            locale: 'en-GB'
          }
        }
      })
    }));
  });
}); 