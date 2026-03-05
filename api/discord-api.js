import crypto from "crypto"

const a = process.env.api_secret

const b = process.env.webhook_exec
const c = process.env.webhook_abuse
const d = process.env.webhook_invalid
const e = process.env.webhook_error

const f = new Map()
const g = new Map()
const h = new Map()
const i = new Map()
const j = new Map()
const k = new Map()

function l(m){
    return crypto.createHash("sha256").update(m).digest("hex")
}

function n(){
    return new Date().toLocaleString("pt-BR",{timeZone:"America/Sao_Paulo"})
}

async function o(p,q,r){

    const s = Date.now()

    const t = k.get(r)

    if(t && s - t < 5000){
        return
    }

    k.set(r,s)

    await fetch(p,{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(q)
    })
}

export default async function handler(req,res){

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress
    const now = Date.now()

    const ua = req.headers["user-agent"] || "desconhecido"
    const method = req.method

    const origin = ua.toLowerCase().includes("mozilla") ? "navegador" : "executor"

    if(j.has(ip)){

        const expire = j.get(ip)

        if(now < expire){
            return res.status(403).end()
        }

        j.delete(ip)
    }

    const {
        username,
        displayname,
        userId,
        experience,
        executor,
        timestamp,
        nonce,
        signature
    } = req.body || {}

    if(!username || !userId || !experience || !timestamp || !nonce || !signature){

        await o(d,{
            embeds:[{
                title:"request invalido",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:String(ua)},
                    {name:"tipo request",value:method},
                    {name:"origem",value:origin},
                    {name:"horario",value:n()}
                ]
            }]
        },ip)

        return res.status(400).end()
    }

    if(Math.abs(now - timestamp) > 10000){

        await o(d,{
            embeds:[{
                title:"request expirado",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:String(ua)},
                    {name:"tipo request",value:method},
                    {name:"horario",value:n()}
                ]
            }]
        },ip)

        return res.status(403).end()
    }

    if(f.has(nonce)){

        await o(c,{
            embeds:[{
                title:"replay detectado",
                fields:[
                    {name:"nonce",value:String(nonce)},
                    {name:"ip",value:String(ip)},
                    {name:"horario",value:n()}
                ]
            }]
        },ip)

        return res.status(403).end()
    }

    f.set(nonce,true)

    const expected = l(`${username}:${userId}:${experience}:${executor}:${timestamp}:${nonce}:${a}`)

    if(expected !== signature){

        await o(d,{
            embeds:[{
                title:"assinatura invalida",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:String(ua)},
                    {name:"tipo request",value:method},
                    {name:"horario",value:n()}
                ]
            }]
        },ip)

        return res.status(403).end()
    }

    const last = g.get(ip)

    if(last && now - last < 3000){

        let attempts = i.get(ip) || 0
        attempts++

        i.set(ip,attempts)

        if(attempts % 10 === 0){

            await o(c,{
                embeds:[{
                    title:"abuse detectado",
                    fields:[
                        {name:"ip",value:String(ip)},
                        {name:"tentativas",value:`x${attempts}`},
                        {name:"user agent",value:String(ua)},
                        {name:"executor",value:String(executor || "desconhecido")},
                        {name:"horario",value:n()}
                    ]
                }]
            },ip)
        }

        if(attempts >= 30){

            j.set(ip, now + 900000)

            await o(c,{
                embeds:[{
                    title:"ip banido",
                    fields:[
                        {name:"ip",value:String(ip)},
                        {name:"tentativas",value:`x${attempts}`},
                        {name:"duracao",value:"15 minutos"},
                        {name:"user agent",value:String(ua)},
                        {name:"executor",value:String(executor || "desconhecido")},
                        {name:"horario",value:n()}
                    ]
                }]
            },ip)
        }

        return res.status(429).end()
    }

    g.set(ip,now)

    const cooldown = h.get(userId)

    if(cooldown && now - cooldown < 15000){
        return res.status(429).end()
    }

    h.set(userId,now)

    try{

        const r = await fetch(`https://users.roblox.com/v1/users/${userId}`)
        const data = await r.json()

        if(!data.name || data.name.toLowerCase() !== username.toLowerCase()){

            await o(d,{
                embeds:[{
                    title:"username mismatch",
                    fields:[
                        {name:"username enviado",value:String(username)},
                        {name:"username real",value:String(data.name || "desconhecido")},
                        {name:"ip",value:String(ip)},
                        {name:"horario",value:n()}
                    ]
                }]
            },ip)

            return res.status(403).end()
        }

        await o(b,{
            embeds:[{
                title:"execucao",
                fields:[
                    {name:"username",value:String(data.name),inline:true},
                    {name:"displayName",value:String(data.displayName),inline:true},
                    {name:"userId",value:String(userId),inline:true},
                    {name:"experiencia",value:String(experience)},
                    {name:"executor",value:String(executor || "desconhecido")},
                    {name:"user agent",value:String(ua)},
                    {name:"ip",value:String(ip)},
                    {name:"tipo request",value:method},
                    {name:"horario",value:n()}
                ]
            }]
        },ip)

        res.status(200).json({success:true})

    }catch{

        await o(e,{
            embeds:[{
                title:"erro interno",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:String(ua)},
                    {name:"horario",value:n()}
                ]
            }]
        },ip)

        res.status(500).end()
    }
}
