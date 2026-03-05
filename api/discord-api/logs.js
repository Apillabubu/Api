import crypto from "crypto"

const a = process.env.discord_webhook
const b = process.env.api_key
const c = process.env.hmac_secret

const d = new Map()
const e = new Map()

function f(g){
    return crypto.createHmac("sha256", c).update(g).digest("hex")
}

function h(){
    return new Date().toLocaleString("pt-BR",{timeZone:"America/Sao_Paulo"})
}

async function i(j){
    await fetch(a,{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(j)
    })
}

export default async function handler(k,l){

    const m = k.headers["x-forwarded-for"] || k.socket.remoteAddress
    const n = Date.now()

    if(k.method !== "POST"){
        await i({
            embeds:[{
                title:"requisicao invalida",
                fields:[
                    {name:"motivo",value:"metodo invalido"},
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })
        return l.status(405).end()
    }

    const o = d.get(m)

    if(o && n - o < 5000){
        await i({
            embeds:[{
                title:"rate limit",
                fields:[
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })
        return l.status(429).end()
    }

    d.set(m,n)

    if(k.headers["x-api-key"] !== b){
        await i({
            embeds:[{
                title:"api key invalida",
                fields:[
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })
        return l.status(401).end()
    }

    const p = k.headers["x-signature"]
    const q = JSON.stringify(k.body)
    const r = f(q)

    if(p !== r){
        await i({
            embeds:[{
                title:"assinatura invalida",
                fields:[
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })
        return l.status(403).end()
    }

    const {username:s,userId:t,experience:u,token:v} = k.body || {}

    if(!s || !t || !u){
        await i({
            embeds:[{
                title:"body invalido",
                fields:[
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })
        return l.status(400).end()
    }

    let w = e.get(m)

    if(!w){
        const x = crypto.randomBytes(32).toString("hex")
        e.set(m,{token:x,criado:n})
        return l.status(200).json({token:x})
    }

    if(w.token !== v){
        await i({
            embeds:[{
                title:"token invalido",
                fields:[
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })
        return l.status(403).end()
    }

    if(n - w.criado > 600000){
        const y = crypto.randomBytes(32).toString("hex")
        e.set(m,{token:y,criado:n})
        return l.status(200).json({token:y})
    }

    try{

        const z = await fetch(`https://users.roblox.com/v1/users/${t}`)
        const aa = await z.json()

        if(!aa.name || aa.name.toLowerCase() !== s.toLowerCase()){
            await i({
                embeds:[{
                    title:"username nao corresponde ao userid",
                    fields:[
                        {name:"username enviado",value:String(s)},
                        {name:"userid enviado",value:String(t)},
                        {name:"username real",value:String(aa.name || "desconhecido")},
                        {name:"ip",value:String(m)},
                        {name:"horario",value:h()}
                    ]
                }]
            })
            return l.status(403).end()
        }

        await i({
            embeds:[{
                title:"execucao",
                fields:[
                    {name:"username",value:String(s),inline:true},
                    {name:"userid",value:String(t),inline:true},
                    {name:"experiencia",value:String(u),inline:true},
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })

        l.status(200).json({success:true})

    }catch{

        await i({
            embeds:[{
                title:"erro interno",
                fields:[
                    {name:"ip",value:String(m)},
                    {name:"horario",value:h()}
                ]
            }]
        })

        l.status(500).end()
    }
}