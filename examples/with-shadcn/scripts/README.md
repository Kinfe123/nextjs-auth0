# Auth0 to Better Auth Migration

This script helps you migrate your users and their data from Auth0 to Better Auth. The script handles:

- User profiles
- Social connections
- Roles and permissions
- User metadata
- Multi-factor authentication settings (if enabled)

## Prerequisites

1. Auth0 Management API credentials:
   - Domain
   - Client ID
   - Client Secret

2. Better Auth setup with required plugins:
   - Admin plugin (for roles)
   - Two Factor plugin (for MFA)
   - Username plugin (if you use usernames)

3. PostgreSQL database connection string

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Auth0 Management API
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret

# Better Auth Database
DATABASE_URL=postgresql://user:password@localhost:5432/better_auth

# Social Providers (if using)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

## Running the Migration

1. Install dependencies:
   ```bash
   pnpm install
   ```

2. Run the migration script:
   ```bash
   pnpm migrate:auth0
   ```

## Migration Process

The script will:

1. Connect to Auth0 using the Management API
2. Fetch all users in batches of 100
3. For each user:
   - Create a user profile in Better Auth
   - Migrate social connections
   - Transfer user metadata
   - Set up MFA if enabled
   - Map Auth0 roles to Better Auth roles

## Post-Migration Steps

1. Verify the migration by checking the Better Auth database
2. Test user logins with different authentication methods
3. Verify MFA settings for users who had it enabled
4. Check that roles and permissions are correctly mapped
5. Update your application to use Better Auth instead of Auth0

## Error Handling

The script includes error handling and logging:
- Failed migrations for individual users won't stop the entire process
- Errors are logged to the console
- You can retry the migration for failed users

## Customization

You can customize the script by:
- Modifying the role mapping function
- Adding custom metadata handling
- Adjusting the batch size for user fetching
- Adding more social providers

## Support

If you encounter any issues:
1. Check the error logs
2. Verify your environment variables
3. Ensure all required plugins are enabled in Better Auth
4. Check your database connection
5. Visit [Better Auth documentation](https://www.better-auth.com/docs) for more information 