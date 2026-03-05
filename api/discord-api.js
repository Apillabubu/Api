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
const j = new Set() 

function k(l){
    return crypto.createHash("sha256").update(l).digest("hex")
}

function m(){
    return new Date().toLocaleString("pt-BR",{timeZone:"America/Sao_Paulo"})
}

async function n(o,p){
    await fetch(o,{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(p)
    })
}

export default async function handler(q,r){

    if(q.method !== "POST"){
        return r.status(405).end()
    }

    const s = q.headers["x-forwarded-for"] || q.socket.remoteAddress
    const t = Date.now()

    if(j.has(s)){
        return r.status(403).end()
    }

    const {
        username:u,
        userId:v,
        experience:w,
        timestamp:x,
        nonce:y,
        signature:z
    } = q.body || {}

    if(!u || !v || !w || !x || !y || !z){

        await n(d,{
            embeds:[{
                title:"request invalido",
                fields:[
                    {name:"ip",value:String(s)},
                    {name:"horario",value:m()}
                ]
            }]
        })

        return r.status(400).end()
    }

    if(Math.abs(t - x) > 10000){

        await n(d,{
            embeds:[{
                title:"request expirado",
                fields:[
                    {name:"ip",value:String(s)},
                    {name:"horario",value:m()}
                ]
            }]
        })

        return r.status(403).end()
    }

    if(f.has(y)){
        return r.status(403).end()
    }

    f.set(y,true)

    const aa = k(`${u}:${v}:${w}:${x}:${y}:${a}`)

    if(aa !== z){

        await n(d,{
            embeds:[{
                title:"assinatura invalida",
                fields:[
                    {name:"ip",value:String(s)},
                    {name:"horario",value:m()}
                ]
            }]
        })

        return r.status(403).end()
    }

    const ab = g.get(s)

    if(ab && t - ab < 3000){

        let ac = i.get(s) || 0
        ac++

        i.set(s,ac)

        if(ac % 10 === 0){

            await n(c,{
                embeds:[{
                    title:"abuse detectado",
                    fields:[
                        {name:"ip",value:String(s)},
                        {name:"tentativas",value:`x${ac}`},
                        {name:"horario",value:m()}
                    ]
                }]
            })
        }

        if(ac >= 30){

            j.add(s)

            await n(c,{
                embeds:[{
                    title:"ip banido",
                    fields:[
                        {name:"ip",value:String(s)},
                        {name:"tentativas",value:`x${ac}`},
                        {name:"motivo",value:"spam"},
                        {name:"horario",value:m()}
                    ]
                }]
            })
        }

        return r.status(429).end()
    }

    g.set(s,t)

    const ad = h.get(v)

    if(ad && t - ad < 15000){
        return r.status(429).end()
    }

    h.set(v,t)

    try{

        const ae = await fetch(`https://users.roblox.com/v1/users/${v}`)
        const af = await ae.json()

        if(!af.name || af.name.toLowerCase() !== u.toLowerCase()){

            await n(d,{
                embeds:[{
                    title:"username mismatch",
                    fields:[
                        {name:"username enviado",value:String(u)},
                        {name:"username real",value:String(af.name || "desconhecido")},
                        {name:"ip",value:String(s)},
                        {name:"horario",value:m()}
                    ]
                }]
            })

            return r.status(403).end()
        }

        await n(b,{
            embeds:[{
                title:"execucao",
                fields:[
                    {name:"username",value:String(u),inline:true},
                    {name:"userid",value:String(v),inline:true},
                    {name:"experiencia",value:String(w),inline:true},
                    {name:"ip",value:String(s)},
                    {name:"horario",value:m()}
                ]
            }]
        })

        r.status(200).json({success:true})

    }catch{

        await n(e,{
            embeds:[{
                title:"erro interno",
                fields:[
                    {name:"ip",value:String(s)},
                    {name:"horario",value:m()}
                ]
            }]
        })

        r.status(500).end()
    }
}
