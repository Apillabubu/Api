import crypto from "crypto"

const secret = process.env.api_secret

const webhook_exec = process.env.webhook_exec
const webhook_abuse = process.env.webhook_abuse
const webhook_invalid = process.env.webhook_invalid
const webhook_error = process.env.webhook_error

const nonce_cache = new Map()
const ip_requests = new Map()
const ip_attempts = new Map()
const ip_bans = new Map()
const webhook_limit = new Map()

function sha(v){
    return crypto.createHash("sha256").update(v).digest("hex")
}

function time(){
    return new Date().toLocaleString("pt-BR",{timeZone:"America/Sao_Paulo"})
}

async function send(url,data,ip){

    const now = Date.now()

    const last = webhook_limit.get(ip)

    if(last && now-last < 4000) return

    webhook_limit.set(ip,now)

    await fetch(url,{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(data)
    })
}

function origin(ua){
    if(!ua) return "unknown"
    return ua.toLowerCase().includes("mozilla") ? "browser" : "executor"
}

export default async function handler(req,res){

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress
    const ua = req.headers["user-agent"] || "unknown"
    const method = req.method
    const now = Date.now()

    const body = req.body || {}

    const {
        username,
        displayname,
        userId,
        experience,
        executor,
        timestamp,
        nonce,
        signature
    } = body

    if(ip_bans.has(ip)){

        const expire = ip_bans.get(ip)

        if(now < expire) return res.status(403).end()

        ip_bans.delete(ip)
    }

    let reqs = ip_requests.get(ip) || []
    reqs = reqs.filter(v => now-v < 3000)

    reqs.push(now)
    ip_requests.set(ip,reqs)

    if(reqs.length >= 3){

        let attempts = ip_attempts.get(ip) || 0
        attempts++
        ip_attempts.set(ip,attempts)

        await send(webhook_abuse,{
            embeds:[{
                title:"ABUSE DETECTADO",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"tentativas",value:`x${attempts}`},
                    {name:"user agent",value:ua},
                    {name:"executor",value:String(executor || "unknown")},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        if(attempts >= 10){

            ip_bans.set(ip, now + 900000)

            await send(webhook_abuse,{
                embeds:[{
                    title:"IP BANIDO",
                    fields:[
                        {name:"ip",value:String(ip)},
                        {name:"tentativas",value:`x${attempts}`},
                        {name:"duracao",value:"15 minutos"},
                        {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                        {name:"horario",value:time()}
                    ]
                }]
            },ip)
        }

        return res.status(429).end()
    }

    if(!username || !userId || !experience || !timestamp || !nonce || !signature){

        await send(webhook_invalid,{
            embeds:[{
                title:"REQUEST INVALIDO",
                fields:[
                    {name:"motivo",value:"missing fields"},
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:ua},
                    {name:"origem",value:origin(ua)},
                    {name:"tipo request",value:method},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        return res.status(400).end()
    }

    if(Math.abs(now - timestamp) > 10000){

        await send(webhook_invalid,{
            embeds:[{
                title:"REQUEST EXPIRADO",
                fields:[
                    {name:"motivo",value:"timestamp expired"},
                    {name:"ip",value:String(ip)},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        return res.status(403).end()
    }

    if(nonce_cache.has(nonce)){

        await send(webhook_abuse,{
            embeds:[{
                title:"REPLAY DETECTADO",
                fields:[
                    {name:"nonce",value:String(nonce)},
                    {name:"ip",value:String(ip)},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        return res.status(403).end()
    }

    nonce_cache.set(nonce,true)

    const expected = sha(`${username}:${userId}:${experience}:${executor}:${timestamp}:${nonce}:${secret}`)

    if(expected !== signature){

        await send(webhook_invalid,{
            embeds:[{
                title:"ASSINATURA INVALIDA",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:ua},
                    {name:"executor",value:String(executor || "unknown")},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        return res.status(403).end()
    }

    try{

        const r = await fetch(`https://users.roblox.com/v1/users/${userId}`)
        const data = await r.json()

        if(!data.name || data.name.toLowerCase() !== username.toLowerCase()){

            await send(webhook_invalid,{
                embeds:[{
                    title:"USERNAME MISMATCH",
                    fields:[
                        {name:"username enviado",value:String(username)},
                        {name:"username real",value:String(data.name || "unknown")},
                        {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                        {name:"horario",value:time()}
                    ]
                }]
            },ip)

            return res.status(403).end()
        }

        await send(webhook_exec,{
            embeds:[{
                title:"EXECUCAO",
                fields:[
                    {name:"username",value:String(data.name),inline:true},
                    {name:"displayName",value:String(data.displayName),inline:true},
                    {name:"userId",value:String(userId),inline:true},
                    {name:"executor",value:String(executor)},
                    {name:"ip",value:String(ip)},
                    {name:"user agent",value:ua},
                    {name:"tipo request",value:method},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        res.status(200).json({success:true})

    }catch{

        await send(webhook_error,{
            embeds:[{
                title:"ERRO INTERNO",
                fields:[
                    {name:"ip",value:String(ip)},
                    {name:"body",value:"```json\n"+JSON.stringify(body,null,2)+"\n```"},
                    {name:"horario",value:time()}
                ]
            }]
        },ip)

        res.status(500).end()
    }
}
