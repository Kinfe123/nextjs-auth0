import { ManagementClient } from 'auth0';
import { betterAuth } from "better-auth";
import { Pool } from "pg";
import { generateRandomString, symmetricEncrypt } from "better-auth/crypto";
import { admin, twoFactor, username } from "better-auth/plugins";
import bcrypt from 'bcryptjs';
import { auth } from '@/lib/auth';


const SUPPORTED_HASH_ALGORITHMS = ['bcrypt'];

const auth0Client = new ManagementClient({
    domain: process.env.AUTH0_DOMAIN!,
    clientId: process.env.AUTH0_CLIENT_ID!,
    clientSecret: process.env.AUTH0_SECRET!,
});

// export const auth = betterAuth({
//     database: new Pool({ 
//         connectionString: process.env.DATABASE_URL 
//     }),
//     emailAndPassword: { 
//         enabled: true,
//     },
//     socialProviders: {
//         github: {
//             clientId: process.env.GITHUB_CLIENT_ID!,
//             clientSecret: process.env.GITHUB_CLIENT_SECRET!,
//         },
//         google: {
//             clientId: process.env.GOOGLE_CLIENT_ID!,
//             clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
//         }
//     },
//     plugins: [
//         admin(),
//         twoFactor(),
//         username(),
//     ],
// });

function safeDateConversion(timestamp?: string | number): Date {
    if (!timestamp) return new Date();
    
    const numericTimestamp = typeof timestamp === 'string' ? Date.parse(timestamp) : timestamp;
    
    const milliseconds = numericTimestamp < 1000000000000 ? numericTimestamp * 1000 : numericTimestamp;
    
    const date = new Date(milliseconds);
    
    if (isNaN(date.getTime())) {
        console.warn(`Invalid timestamp: ${timestamp}, falling back to current date`);
        return new Date();
    }
    
    // Check for unreasonable dates (before 2000 or after 2100)
    const year = date.getFullYear();
    if (year < 2000 || year > 2100) {
        console.warn(`Suspicious date year: ${year}, falling back to current date`);
        return new Date();
    }
    
    return date;
}

// Helper function to generate backup codes for 2FA
async function generateBackupCodes(secret: string) {
    const key = secret;
    const backupCodes = Array.from({ length: 10 })
        .fill(null)
        .map(() => generateRandomString(10, "a-z", "0-9", "A-Z"))
        .map((code) => `${code.slice(0, 5)}-${code.slice(5)}`);
    
    const encCodes = await symmetricEncrypt({
        data: JSON.stringify(backupCodes),
        key: key,
    });
    return encCodes;
}

// Function to map Auth0 roles to Better Auth roles
function mapAuth0RoleToBetterAuthRole(auth0Roles: string[]): string {
    if (auth0Roles.includes('admin')) return 'admin';
    if (auth0Roles.includes('moderator')) return 'moderator';
    return 'user';
}

// Helper function to handle password migration
async function migratePassword(auth0User: any) {
    if (auth0User.password_hash) {
        if (auth0User.password_hash.startsWith('$2a$') || auth0User.password_hash.startsWith('$2b$')) {
            return auth0User.password_hash;
        }
    }

    if (auth0User.custom_password_hash) {
        const customHash = auth0User.custom_password_hash;

        if (customHash.algorithm === 'bcrypt') {
            const hash = customHash.hash.value;
            if (hash.startsWith('$2a$') || hash.startsWith('$2b$')) {
                return hash;
            }
        }

        return JSON.stringify({
            algorithm: customHash.algorithm,
            hash: {
                value: customHash.hash.value,
                encoding: customHash.hash.encoding || 'utf8',
                ...(customHash.hash.digest && { digest: customHash.hash.digest }),
                ...(customHash.hash.key && { 
                    key: {
                        value: customHash.hash.key.value,
                        encoding: customHash.hash.key.encoding || 'utf8'
                    }
                })
            },
            ...(customHash.salt && {
                salt: {
                    value: customHash.salt.value,
                    encoding: customHash.salt.encoding || 'utf8',
                    position: customHash.salt.position || 'prefix'
                }
            }),
            ...(customHash.password && {
                password: {
                    encoding: customHash.password.encoding || 'utf8'
                }
            }),
            ...(customHash.algorithm === 'scrypt' && {
                keylen: customHash.keylen,
                cost: customHash.cost || 16384,
                blockSize: customHash.blockSize || 8,
                parallelization: customHash.parallelization || 1
            })
        });
    }
    
    return null;
}

async function migrateMFAFactors(auth0User: any, userId: string | undefined, ctx: any) {
    if (!userId || !auth0User.mfa_factors || !Array.isArray(auth0User.mfa_factors)) {
        return;
    }

    for (const factor of auth0User.mfa_factors) {
        try {
            if (factor.totp && factor.totp.secret) {
                await ctx.adapter.create({
                    model: "twoFactor",
                    data: {
                        userId: userId,
                        secret: factor.totp.secret,
                        backupCodes: await generateBackupCodes(factor.totp.secret)
                    }
                });
            }
        } catch (error) {
            console.error(`Failed to migrate MFA factor for user ${userId}:`, error);
        }
    }
}

async function migrateOAuthAccounts(auth0User: any, userId: string | undefined, ctx: any) {
    if (!userId || !auth0User.identities || !Array.isArray(auth0User.identities)) {
        return;
    }

    for (const identity of auth0User.identities) {
        try {
            if (identity.provider !== 'auth0') {
                const providerMapping: { [key: string]: string } = {
                    'google-oauth2': 'google',
                    'github': 'github',
                    'facebook': 'facebook',
                    'twitter': 'twitter',
                    'microsoft': 'azure-ad',
                    'linkedin': 'linkedin',
                    'apple': 'apple'
                };

                const providerId = providerMapping[identity.provider] || identity.provider;

                await ctx.adapter.create({
                    model: "account",
                    data: {
                        id: `${auth0User.user_id}|${identity.provider}|${identity.user_id}`,
                        userId: userId,
                        type: "oauth",
                        provider: providerId,
                        accountId: identity.user_id,
                        // Store OAuth-specific data
                        access_token: identity.access_token,
                        token_type: identity.token_type,
                        refresh_token: identity.refresh_token,
                        expires_at: identity.expires_in ? Math.floor(Date.now() / 1000) + identity.expires_in : undefined,
                        scope: identity.scope,
                        id_token: identity.id_token,
                        session_state: identity.session_state,
                        // Store additional profile data
                        profile: {
                            email: identity.profileData?.email,
                            name: identity.profileData?.name,
                            picture: identity.profileData?.picture,
                            sub: identity.user_id
                        },
                        createdAt: safeDateConversion(auth0User.created_at),
                        updatedAt: safeDateConversion(auth0User.updated_at)
                    },
                    forceAllowId: true
                }).catch((error: Error) => {
                    console.error(`Failed to create OAuth account for user ${userId} with provider ${providerId}:`, error);
                    return ctx.adapter.create({
                    // Try creating without optional fields if the first attempt failed
                        model: "account",
                        data: {
                            id: `${auth0User.user_id}|${identity.provider}|${identity.user_id}`,
                            userId: userId,
                            type: "oauth",
                            provider: providerId,
                            accountId: identity.user_id,
                            access_token: identity.access_token,
                            token_type: identity.token_type,
                            refresh_token: identity.refresh_token,
                            expires_at: identity.expires_in ? Math.floor(Date.now() / 1000) + identity.expires_in : undefined,
                            scope: identity.scope,
                            id_token: identity.id_token,
                            createdAt: safeDateConversion(auth0User.created_at),
                            updatedAt: safeDateConversion(auth0User.updated_at)
                        },
                        forceAllowId: true
                    });
                });

                console.log(`Successfully migrated OAuth account for user ${userId} with provider ${providerId}`);
            }
        } catch (error) {
            console.error(`Failed to migrate OAuth account for user ${userId}:`, error);
        }
    }
}

async function migrateFromAuth0() {
    try {
        const ctx = await auth.$context;
        const isAdminEnabled = ctx.options?.plugins?.find(plugin => plugin.id === "admin");
        const isTwoFactorEnabled = ctx.options?.plugins?.find(plugin => plugin.id === "two-factor");
        const isUsernameEnabled = ctx.options?.plugins?.find(plugin => plugin.id === "username");

        const perPage = 100;
        const auth0Users: any[] = [];
        let pageNumber = 0;

        while (true) {
            try {
                const params = {
                    per_page: perPage,
                    page: pageNumber,
                    include_totals: true,
                };
                const response = (await auth0Client.users.getAll(params)).data as any;
                const users = response.users || [];
                
                if (users.length === 0) break;
                
                auth0Users.push(...users);
                pageNumber++;
                
                if (users.length < perPage) break;
            } catch (error) {
                console.error('Error fetching users:', error);
                break;
            }
        }

        console.log(`Found ${auth0Users.length} users to migrate`);

        for (const auth0User of auth0Users) {
            try {
                // Determine if this is a password-based or OAuth user
                const isOAuthUser = auth0User.identities?.some((identity: any) => identity.provider !== 'auth0');
                console.log('auth0User', auth0User)
                // Base user data that's common for both types
                const baseUserData = {
                    email: auth0User.email,
                    emailVerified: auth0User.email_verified || false,
                    name: auth0User.name || auth0User.nickname,
                    image: auth0User.picture,
                    createdAt: safeDateConversion(auth0User.created_at),
                    updatedAt: safeDateConversion(auth0User.updated_at),
                    // lastLoginAt: safeDateConversion(auth0User.last_login),
                    // lastLoginIp: auth0User.last_ip,
                    // loginCount: auth0User.logins_count || 0,
                };

                console.log('baseUserData', baseUserData , isOAuthUser)
                const createdUser = await ctx.adapter.create({
                    model: "user",
                    data: {
                        ...baseUserData,
                        ...(isOAuthUser ? {} : {
                            username: auth0User.nickname,
                            password: await migratePassword(auth0User),
                        }),
                    },
                });

                if (!createdUser?.id) {
                    throw new Error('Failed to create user');
                }

                // For OAuth users, migrate their OAuth accounts
                if (isOAuthUser) {
                    for (const identity of auth0User.identities) {
                        if (identity.provider !== 'auth0') {
                            const providerId = identity.provider.split("-")[0] || identity.provider;
                            console.log('providerId', providerId)
                            await ctx.adapter.create({
                                model: "account",
                                data: {
                                    userId: createdUser.id,
                                    providerId: providerId,
                                    accountId: identity.user_id,
                                    accessToken: identity.access_token,
                                    refreshToken: identity.refresh_token,
                                    expiresAt: identity.expires_in ? Math.floor(Date.now() / 1000) + identity.expires_in : undefined,
                                    scope: identity.scope,
                                    idToken: identity.id_token,
                                    createdAt: safeDateConversion(auth0User.created_at),
                                    updatedAt: safeDateConversion(auth0User.updated_at)
                                }
                            }).catch(async (error: Error) => {
                                console.error(`Failed to create OAuth account for user ${createdUser.id} with provider ${providerId}:`, error);
                                // Fallback to minimal account data if full data fails
                                await ctx.adapter.create({
                                    model: "account",
                                    data: {
                                        userId: createdUser.id,
                                        providerId: providerId,
                                        accountId: identity.user_id,
                                        createdAt: safeDateConversion(auth0User.created_at),
                                        updatedAt: safeDateConversion(auth0User.updated_at)
                                    }
                                });
                            });
                        }
                    }
                }

                console.log(`Successfully migrated user: ${auth0User.email}`);
            } catch (error) {
                console.error(`Failed to migrate user ${auth0User.email}:`, error);
            }
        }

        console.log('Migration completed successfully');
    } catch (error) {
        console.error('Migration failed:', error);
        throw error;
    }
}

migrateFromAuth0()
    .then(() => {
        console.log('Migration completed');
        process.exit(0);
    })
    .catch((error) => {
        console.error('Migration failed:', error);
        process.exit(1);
    }); 