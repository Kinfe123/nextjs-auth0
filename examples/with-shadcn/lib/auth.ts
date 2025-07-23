import { betterAuth } from "better-auth";
import { admin, openAPI, organization, twoFactor, username } from "better-auth/plugins";
import { prismaAdapter } from "better-auth/adapters/prisma";
import prisma from "@/lib/prisma"
import bcrypt from "bcrypt";
export const auth = betterAuth({
    database: prismaAdapter(prisma, {
        provider: "postgresql",
    }),
    emailAndPassword: {
        enabled: true,
        password: {
            hash: async (password) => {
                console.log("Password being generated") 
                return await bcrypt.hash(password, 10);
            },
            verify: async (data) => {
                console.log("Password being verified", data)
                const rr = await bcrypt.hash(data.password, 10);
                console.log("RR", rr)
                const result = await bcrypt.compare(data.password, data.hash);
                console.log("Result", result)
                return result;
            }

        }
    },
    socialProviders: {
        github: {
            clientId: process.env.GITHUB_CLIENT_ID!,
            clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        },
        google: {
            clientId: process.env.GOOGLE_CLIENT_ID!,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        }
    },
    advanced: {
    
    },
    plugins: [
        admin(),
        twoFactor(),
        username(),
        organization(),
        openAPI()
    ],
});