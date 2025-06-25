import { ManagementClient } from 'auth0';
import { betterAuth } from "better-auth";
import { Pool } from "pg";
import { generateRandomString, symmetricEncrypt } from "better-auth/crypto";
import { admin, twoFactor, username } from "better-auth/plugins";
import bcrypt from 'bcryptjs';
import { auth } from '@/lib/auth';


const SUPPORTED_HASH_ALGORITHMS = ['bcrypt'];

const auth0Client = new ManagementClient({
    domain: AUTH0_DOMAIN,
    clientId: AUTH0_CLIENT_ID,
    clientSecret: AUTH0_SECRET,
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

            if (factor.phone && factor.phone.value) {
                await ctx.adapter.create({
                    model: "phoneNumber",
                    data: {
                        userId: userId,
                        phoneNumber: factor.phone.value,
                        verified: true
                    }
                });
            }

            if (factor.email && factor.email.value) {
                await ctx.adapter.create({
                    model: "emailMFA",
                    data: {
                        userId: userId,
                        email: factor.email.value,
                        verified: true
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
                        providerAccountId: identity.user_id,
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
                            providerAccountId: identity.user_id,
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

        // Get all users from Auth0
        let auth0Users: any[] = [];
        let pageNumber = 0;
        const perPage = 100;
        
        while (true) {
            try {
                const params = {
                    page: pageNumber,
                    per_page: perPage,
                    include_totals: true
                };
                const response = (await auth0Client.users.getAll(params)).data as any;
                const users = response.users;
                if (users.length === 0) break;
                auth0Users = auth0Users.concat(users);
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
                const passwordHash = await migratePassword(auth0User);

                const createdUser = await ctx.adapter.create<{
                    id: string;
                }>({
                    model: "user",
                    data: {
                        id: auth0User.user_id,
                        email: auth0User.email,
                        emailVerified: auth0User.email_verified || false,
                        name: auth0User.name || `${auth0User.given_name || ''} ${auth0User.family_name || ''}`.trim(),
                        image: auth0User.picture,
                        createdAt: safeDateConversion(auth0User.created_at),
                        updatedAt: safeDateConversion(auth0User.updated_at),
                        
                        // Password hash
                        ...(passwordHash ? {
                            password: passwordHash
                        } : {}),
                        
                        // Admin plugin data
                        ...(isAdminEnabled ? {
                            banned: auth0User.blocked || false,
                            role: mapAuth0RoleToBetterAuthRole(auth0User.roles || []),
                        } : {}),
                        
                        // Username plugin data
                        ...(isUsernameEnabled ? {
                            username: auth0User.username || auth0User.nickname,
                        } : {}),

                        // Additional fields from schema
                        given_name: auth0User.given_name,
                        family_name: auth0User.family_name,
                        nickname: auth0User.nickname,
                    },
                    forceAllowId: true
                }).catch(async e => {
                    return await ctx.adapter.findOne<{
                        id: string;
                    }>({
                        model: "user",
                        where: [{
                            field: "id",
                            value: auth0User.user_id || ""
                        }]
                    });
                });

                await migrateOAuthAccounts(auth0User, createdUser?.id, ctx);

                if (isTwoFactorEnabled) {
                    await migrateMFAFactors(auth0User, createdUser?.id, ctx);
                }

                console.log(`Successfully migrated user ${auth0User.email}`);
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