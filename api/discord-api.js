import crypto from "crypto"

const a = process.env.discord_webhook
const b = process.env.api_key

const c = new Map()
const d = new Map()
const e = new Set()

function f(){
    return new Date().toLocaleString("pt-BR",{timeZone:"America/Sao_Paulo"})
}

async function g(h){
    await fetch(a,{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(h)
    })
}

export default async function handler(i,j){

    const k = i.headers["x-forwarded-for"] || i.socket.remoteAddress
    const l = Date.now()

    if(e.has(k)){
        return j.status(403).end()
    }

    if(i.method !== "POST"){
        await g({
            embeds:[{
                title:"requisicao invalida",
                fields:[
                    {name:"motivo",value:"metodo invalido"},
                    {name:"ip",value:String(k)},
                    {name:"horario",value:f()}
                ]
            }]
        })
        return j.status(405).end()
    }

    const m = c.get(k)

    if(m && l - m < 5000){

        if(!d.has(k)) d.set(k,0)
        d.set(k,d.get(k)+1)

        if(d.get(k) > 5){
            e.add(k)

            await g({
                embeds:[{
                    title:"ip bloqueado",
                    fields:[
                        {name:"ip",value:String(k)},
                        {name:"motivo",value:"spam"},
                        {name:"horario",value:f()}
                    ]
                }]
            })
        }

        return j.status(429).end()
    }

    c.set(k,l)

    if(i.headers["x-api-key"] !== b){
        await g({
            embeds:[{
                title:"api key invalida",
                fields:[
                    {name:"ip",value:String(k)},
                    {name:"horario",value:f()}
                ]
            }]
        })
        return j.status(401).end()
    }

    const {username:n,userId:o,experience:p} = i.body || {}

    if(!n || !o || !p){
        await g({
            embeds:[{
                title:"body invalido",
                fields:[
                    {name:"ip",value:String(k)},
                    {name:"horario",value:f()}
                ]
            }]
        })
        return j.status(400).end()
    }

    try{

        const q = await fetch(`https://users.roblox.com/v1/users/${o}`)
        const r = await q.json()

        if(!r.name || r.name.toLowerCase() !== n.toLowerCase()){
            await g({
                embeds:[{
                    title:"username nao corresponde ao userid",
                    fields:[
                        {name:"username enviado",value:String(n)},
                        {name:"userid enviado",value:String(o)},
                        {name:"username real",value:String(r.name || "desconhecido")},
                        {name:"ip",value:String(k)},
                        {name:"horario",value:f()}
                    ]
                }]
            })
            return j.status(403).end()
        }

        await g({
            embeds:[{
                title:"execucao",
                fields:[
                    {name:"username",value:String(n),inline:true},
                    {name:"userid",value:String(o),inline:true},
                    {name:"experiencia",value:String(p),inline:true},
                    {name:"ip",value:String(k)},
                    {name:"horario",value:f()}
                ]
            }]
        })

        j.status(200).json({success:true})

    }catch{

        await g({
            embeds:[{
                title:"erro interno",
                fields:[
                    {name:"ip",value:String(k)},
                    {name:"horario",value:f()}
                ]
            }]
        })

        j.status(500).end()
    }
}
