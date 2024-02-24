import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from 'next-auth/providers/credentials'
import { z } from 'zod'
import { User } from "./app/lib/definitions";
import { sql } from "@vercel/postgres";
import bcrypt from 'bcrypt'


// async function getUser(email:string) : Promise<User | undefined> {
//     try {
//         const user = await sql<User>`SELECT * from USERS where email=${email}`;
//         return user.rows[0];
//     } catch (error) {
//         console.error('Failed to fetch user: ', error);
//         throw new Error('Failed to fetch user.');
//     }
    
// }
const getUser = async ({ email, password }: {email: string, password: string}) => {
    try {
        const res = await fetch('http://localhost:4000/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: email,
                password
            })
        })
        if (res.ok) {
            return res.json();
        }
    } catch (error) {
        console.log(error)
    }
}
export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials) {
            const parsedCredentials = z.
                object({
                    email: z.string().email(),
                    password: z.string().min(6)
                })
                .safeParse(credentials);
            if (parsedCredentials.success) {
                const {email, password} = parsedCredentials.data;
                // const user = await getUser(email);
                // if (!user) return null;
                // const passwordsMatch = await bcrypt.compare(password, user.password);

                // if (passwordsMatch) return user;
                try {
                    const user = await getUser({email, password});
                return user;
                } catch (err) {
                    console.log(err)
                    throw new Error("Not login");
                }
            }
            console.log('Invalid credentials');
            return null;
        }
    })],
})