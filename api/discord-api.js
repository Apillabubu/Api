import crypto from "crypto"

const a = process.env.discord_webhook
const b = process.env.api_key

const c = new Map()
const d = new Map()
const e = new Map()
const f = new Set()

function g(){
    return new Date().toLocaleString("pt-BR",{timeZone:"America/Sao_Paulo"})
}

async function h(i){
    await fetch(a,{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(i)
    })
}

export default async function handler(j,k){

    const l = j.headers["x-forwarded-for"] || j.socket.remoteAddress
    const m = Date.now()

    if(f.has(l)){
        return k.status(403).end()
    }

    if(j.method !== "POST"){
        await h({
            embeds:[{
                title:"requisicao invalida",
                fields:[
                    {name:"motivo",value:"metodo invalido"},
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })
        return k.status(405).end()
    }

    const n = c.get(l)

    if(n && m - n < 5000){
        await h({
            embeds:[{
                title:"rate limit",
                fields:[
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })

        if(!e.has(l)) e.set(l,0)
        e.set(l,e.get(l)+1)

        if(e.get(l) > 5){
            f.add(l)

            await h({
                embeds:[{
                    title:"ip bloqueado",
                    fields:[
                        {name:"ip",value:String(l)},
                        {name:"motivo",value:"spam"},
                        {name:"horario",value:g()}
                    ]
                }]
            })
        }

        return k.status(429).end()
    }

    c.set(l,m)

    if(j.headers["x-api-key"] !== b){
        await h({
            embeds:[{
                title:"api key invalida",
                fields:[
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })
        return k.status(401).end()
    }

    const {username:o,userId:p,experience:q,token:r} = j.body || {}

    if(!o || !p || !q){
        await h({
            embeds:[{
                title:"body invalido",
                fields:[
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })
        return k.status(400).end()
    }

    let s = d.get(l)

    if(!s){
        const t = crypto.randomBytes(32).toString("hex")
        d.set(l,{token:t,criado:m})
        return k.status(200).json({token:t})
    }

    if(s.token !== r){
        await h({
            embeds:[{
                title:"token invalido",
                fields:[
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })
        return k.status(403).end()
    }

    if(m - s.criado > 600000){
        const u = crypto.randomBytes(32).toString("hex")
        d.set(l,{token:u,criado:m})
        return k.status(200).json({token:u})
    }

    try{

        const v = await fetch(`https://users.roblox.com/v1/users/${p}`)
        const w = await v.json()

        if(!w.name || w.name.toLowerCase() !== o.toLowerCase()){
            await h({
                embeds:[{
                    title:"username nao corresponde ao userid",
                    fields:[
                        {name:"username enviado",value:String(o)},
                        {name:"userid enviado",value:String(p)},
                        {name:"username real",value:String(w.name || "desconhecido")},
                        {name:"ip",value:String(l)},
                        {name:"horario",value:g()}
                    ]
                }]
            })
            return k.status(403).end()
        }

        await h({
            embeds:[{
                title:"execucao",
                fields:[
                    {name:"username",value:String(o),inline:true},
                    {name:"userid",value:String(p),inline:true},
                    {name:"experiencia",value:String(q),inline:true},
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })

        k.status(200).json({success:true})

    }catch{

        await h({
            embeds:[{
                title:"erro interno",
                fields:[
                    {name:"ip",value:String(l)},
                    {name:"horario",value:g()}
                ]
            }]
        })

        k.status(500).end()
    }
}
