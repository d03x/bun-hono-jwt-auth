import { Hono } from "hono";
import prisma from "./utils/prisma";
import { Jwt } from "hono/utils/jwt";
import { JwtTokenExpired, JwtTokenInvalid } from "hono/utils/jwt/types";

const app = new Hono()

app.post("/register", async function (c) {
    const request = await c.req.json();
    await prisma.user.create({
        data: {
            email: request.email,
            password: await Bun.password.hash(request.password),
            name: request.nama,
        }
    })
    return c.json(request);
});
app.post("/login", async function (c) {
    const jsonBody = await c.req.json();
    //cek email nya dari database
    const user = await prisma.user.findFirst()
    if (!user) {
        return c.json({
            error: true,
            message: "User tidak ditemukan"
        }, 404)
    }
    //validate password
    const validated = await Bun.password.verify(jsonBody.password, user.password);
    if (!validated) {
        return c.json({
            error: true,
            message: "Email atau kata sandi salah"
        }, 403)
    }
    //jika passwordnya sesuai buat token
    const token = await Jwt.sign({
        id: user.id,
        exp: Math.floor(Date.now() / 1000) + 60 * 10,//set token masa aktifnya 10 menit
    }, process?.env?.ACCESS_TOKEN_SIGNATURE as string)
    const masaAktifRefreshToken = Math.floor(Date.now() / 1000) + (60 * 60) * 24;
    const regreshToken = await Jwt.sign({
        id: user.id,
        exp: masaAktifRefreshToken,//set token masa aktifnya 1 hari
    }, process?.env?.ACCESS_TOKEN_SIGNATURE as string)
    //sekarang masukan refresh token ke database
    await prisma.refreshToken.create({
        data: {
            token: regreshToken,
            expiredAt: masaAktifRefreshToken,
            userId: user.id,
        }
    })
    return c.json({
        user: {
            name: user.name,
            email: user.email,
            id: user.id,
        },
        token: token,
        refreshToken: regreshToken,
    })
});
app.get("/me", async function (c) {
    const authorization = await c.req.header()?.authorization;
    if (!authorization) {
        c.status(403)
        return c.json({
            message: "Aksess token tidak valid"
        })
    }
    const authorizationToken = authorization.replace("Bearer ", "")
    //sekarang verifikasi authorization token dan dapatkan payloadnya
    try {
        const verify = await Jwt.verify(authorizationToken, process.env.ACCESS_TOKEN_SIGNATURE as string)
        if (verify) {
            //cek user  nya di database
            const user = await prisma.user.findFirst({
                where: {
                    id: verify.id as string
                }
            });
            return c.json({
                data: user,
            }, 200);
        }
    } catch (e: any) {
        if (e instanceof JwtTokenInvalid) {
            return c.json({
                message: "Token jwt Invalid"
            }, 401)
        } else if (e instanceof JwtTokenExpired) {
            return c.json({
                message: "Token jwt Expired"
            }, 401)
        }
    }
})

app.post("/refresh-token", async function (c) {
    const { token } = await c.req.json()
    try {
        await Jwt.verify(token, process?.env?.ACCESS_TOKEN_SIGNATURE as string)
        //sekarang ambil refresh token dari database 
        const refreshTokenFromDb = await prisma.refreshToken.findFirst({
            where: {
                token: token,
            },
            include: {
                user: true,
            }
        })
        if (refreshTokenFromDb && refreshTokenFromDb?.revoke === false) {
            //user 
            //buat refresh token baru
            const masaAktifRefreshToken = Math.floor(Date.now() / 1000) + (60 * 60) * 24;
            const newRefeshToken = await Jwt.sign({
                id: refreshTokenFromDb.user.id,
                exp: masaAktifRefreshToken,//set token masa aktifnya 1 hari
            }, process?.env?.ACCESS_TOKEN_SIGNATURE as string)
            //tambah ke database refresh token baru
            if (await prisma.refreshToken.create({
                data: {
                    userId: refreshTokenFromDb.user.id,
                    token: newRefeshToken,
                    expiredAt: masaAktifRefreshToken,
                }
            })) {
                await prisma.refreshToken.delete({
                    where: {
                        id: refreshTokenFromDb.id
                    }
                });
                const token = await Jwt.sign({
                    id: refreshTokenFromDb.user.id,
                    exp: Math.floor(Date.now() / 1000) + 60 * 10,//set token masa aktifnya 1 hari
                }, process?.env?.ACCESS_TOKEN_SIGNATURE as string)

                return c.json({
                    refreshToken: newRefeshToken,
                    token: token,
                })
            }
        } else {
            return c.json({
                message: "Refresh token jwt tidak valid"
            }, 401)
        }
    } catch (error) {
        console.log(error);
        return c.json({})
    }

})
export default app;