/**
 * A plugin that provide encapsulated routes
 * @param {FastifyInstance} fastify encapsulated fastify instance
 * @param {Object} options plugin options, refer to https://www.fastify.io/docs/latest/Reference/Plugins/#plugin-options
 */

const {ObjectId} = require('@fastify/mongodb')
const fastify = require('fastify')
const fs = require('fs')
const crypto = require('crypto')
const { type } = require('os')
const { isArray } = require('util')
const jwt = require('jsonwebtoken');
const { json } = require('express')



async function routes (fastify, options) {


  let rl = [];

  const userBodyJsonSchema = {
    "type": "object",
    "properties": {
      "email": {
        "type": "string"
      },
      "password": {
        "type": "string"
      }
    },
    "required": ["email", "password"]
  }

  const dataBodyJsonSchema = {
    "type": "object",
    "properties": {
      "file": {
        "type": "string"
      },
      "contenuto": {
        "type": "string"
      },
      "token": {
        "type": "string"
      }
    },
    "required": ["file", "contenuto", "token"]
  }
  
  const schema = {
    body: userBodyJsonSchema
  }

  const schemaDati = {
    body: dataBodyJsonSchema
  }

  function leggiDisco(path){
    return new Promise((resolve,reject) => {
      fs.readFile(path, 'utf8', (err, data) => {
        if (err) throw err;
        resolve(data);
      })
    });
  }

  function scriviDisco(path,data) {
    return new Promise((resolve,reject) => {
      fs.writeFile(path, data, (err) => {
        if (err) throw err;
        resolve();
      })
    });
  }

  function statoDisco(path){
    return new Promise((resolve,reject)=>{
      fs.stat(path, (err, stat)=>{
        if(err) throw err;
        resolve(stat);
      })
    })
  }

  function verificaToken(token){
    return new Promise((resolve,reject)=>{
      jwt.verify(token, 'my_secret_key', (err,decoded)=>{
        if(err)
          reject();

        resolve(decoded); 
      }) 
    })
  }


    fastify.get('/', async (request, res) => {
      return { hello: 'world' }
    })
  
    


    fastify.post('/register', {schema} ,async(req, res)=>{
      
      const{
        email,
        password
      } = req.body

      const hash = crypto.createHash('sha256').update(password).digest('base64'); 
      
      const result = {
        "email": email,
        "password":hash,
        "tipo_utente":0
      }

      const stat = await statoDisco('data/users.json')
       
      //se il file JSON è vuoto...
      if (stat.size === 0) {

        //è l'unico modo per definire il primo json come array di 1 elemento
        let jsonData = JSON.stringify(result);
        jsonData = '[' + jsonData + ']';

        await scriviDisco('data/users.json', jsonData);
        res.code(200).send({message:"Ti sei registato!"});
        return;

      } 

      const data = await leggiDisco('data/users.json')
      
      
      // Parse the JSON data to an object
      const jsonData = JSON.parse(data);


      let filter = jsonData.filter(element =>{
        return element.email === email;
      })

      if(filter.length === 0) {
        // Add new data to the JSON object
        jsonData.push(result);
      
        // Convert the JSON data to a string
        const updatedData = JSON.stringify(jsonData);

        await scriviDisco('data/users.json',updatedData);
        res.code(200).send({message:"Ti sei registato!"});

        return;
      }
      
      res.code(403).send({message:'Email già in uso. Prova a registrarti con un altra email'});
    
    })


    fastify.post('/login', {schema}, async(req, res)=>{
      
      const{
        email,
        password
      } = req.body

      const hash = crypto.createHash('sha256').update(password).digest('base64'); 

      const data = await leggiDisco("data/users.json");
      
      // Parse the JSON data to an object
      const jsonData = JSON.parse(data);
    
      // Add new data to the JSON object
      let jsonArray = [];

      // Itera su ogni elemento del JSON e lo aggiunge all'array
      jsonData.forEach(element => {
        jsonArray.push(element);
      });

      jsonArray = jsonArray.find((user)=> {return user.email === email})
      

      //se la find non trova nessuna email nel richiamare jsonArray.password ci sarebbe un eccezione quindi bisogna usare TRY-CATCH
      try{
        if(jsonArray.password === hash){

          let token;
          if(jsonArray.tipo_utente===1)
            token = jwt.sign({email:jsonArray.email, admin:true}, 'my_secret_key');
          else
            token = jwt.sign({email:jsonArray.email, admin:false}, 'my_secret_key');

          res.send({message: token})
          return;
        }

        res.code(401).send({ message: 'Credenziali non valide' })

      }catch{
        res.code(401).send({ message: 'Credenziali non valide' })
      }
      
      
      
    })


    fastify.post('/logout', async(req, res) => {
      const {
        token
      } = req.body
      

  
      if(rl.includes(token)){
        res.code(403).send({message: "errore di autenticazione1"})
        return;
      }

      try{
        const verifica = await verificaToken(token);
        res.code(200).send({message: "logout effettuato"})
        rl.push(token)

      }catch{
        res.code(403).send({message: "errore di autenticazione2"})
      }


    });



    fastify.post('/data', {schemaDati}, async(req,res)=>{

      const token = req.body.token;
      const contenuto = btoa(req.body.contenuto);
      const fileName = req.body.file;

      if(rl.includes(token)){
        res.code(403).send({message: "errore di autenticazione1"})
        return;
      }

      let decoded;

      try{
        decoded = await verificaToken(token);  

      }catch{
        res.code(403).send({message: "errore di autenticazione2"})
      }
        

      var result = {
        "email": decoded.email,
        "file": fileName,
        "contenuto": contenuto
      }

      
      const stat = await statoDisco("data/dati.json");
        
      //se il file JSON è vuoto...
      if (stat.size === 0) {

        //è l'unico modo per definire il primo json come array di 1 elemento
        let jsonData = JSON.stringify(result);

        jsonData = '[' + jsonData + ']';
      

        await scriviDisco('data/dati.json',jsonData);
        res.code(200).send({message:'Primo elemento aggiunto al file'});
        return;
       
        
      } 
      
      
      const data = await leggiDisco('data/dati.json');
      
      // Parse the JSON data to an object
      const jsonData = JSON.parse(data);


      let filter = jsonData.filter(element=>{
        return element.file === fileName && element.email === decoded.email;
      })

      if(filter.length === 0){
        jsonData.push(result);
    
        // Convert the JSON data to a string
        const updatedData = JSON.stringify(jsonData);

        await scriviDisco('data/dati.json', updatedData)
        res.code(200).send({message:'I dati sono stati scritti nel file!'});
        return;

      }

      res.code(404).send({message:"Possiedi già un file con questo nome"})
      return;
      
    })

    fastify.get('/data/:key', async (req,res)=>{

      //parametro ALL che se specificato e impostato a 1 da un utente admin correttamente loggato ritorna tutti i file con il nome "KEY" (non solo i suoi)
      const { token,all } = req.query;
      
      if(rl.includes(token)){
        res.code(403).send({message: "errore di autenticazione1"})
        return;
      }

      let decoded;
      try{
        decoded = await verificaToken(token);
      }catch{
        res.code(403).send({message: "errore di autenticazione2"})
        return;
      }
          
      const file = req.params.key;

      if(all == 1){
        
        if(!decoded.admin){ //verifico se l'utente che sta facendo la richiesta è un admin o no

          const data = await leggiDisco('data/dati.json');
          
          const jsonData = JSON.parse(data);

          let jsonArray = [];

          //Itera su ogni elemento del JSON e lo aggiunge all'array
          jsonData.forEach(element => {
            if(element.file === file && element.email === decoded.email)
              jsonArray.push(element);
          });
  
          
          if(jsonArray.length === 0){
            res.code(403).send({message: "Non ci sono file con questo nome"})
            return;
          }
          
          const contenuto = atob(jsonArray[0].contenuto);
          res.code(200).send({contenuto: contenuto});
          return;
        }

        const data = await leggiDisco('data/dati.json');
       
        const jsonData = JSON.parse(data);

        let jsonArray = [];

        // Itera su ogni elemento del JSON e lo aggiunge all'array
        jsonData.forEach(element => {
          if(element.file === file)
            jsonArray.push(element);
        });

        
        if(jsonArray.length === 0){
          res.code(403).send({message: "Non ci sono file con questo nome"})
          return;
        }
        
        let contenuto;
        let files = [];
        let json;
        jsonArray.forEach(element =>{

          contenuto = atob(element.contenuto);
          json = {
            proprietario: element.email,
            contenuto: contenuto
          }
          files.push(json);
        })
        res.code(200).send({
            files
        });
        
      
      }
      //se ALL non è 1 NON verifico neanche se la richiesta è fatta da un admin o meno
      else{
        const data = await leggiDisco('data/dati.json')
        
        const jsonData = JSON.parse(data);

        let jsonArray = [];

        // Itera su ogni elemento del JSON e lo aggiunge all'array
        jsonData.forEach(element => {
          if(element.file === file && element.email === decoded.email)
            jsonArray.push(element);
        });

        
        if(jsonArray.length === 0){
          res.code(403).send({message: "Non ci sono file con questo nome"})
        }
        else{
          const contenuto = atob(jsonArray[0].contenuto);
          res.code(200).send({contenuto: contenuto});

        }
      }
    })


    fastify.patch('/data/:key', async (req,res)=>{
      const token = req.body.token;
      const contenutoNuovo = btoa(req.body.contenuto);
      const utente = req.body.email;
      
      if(rl.includes(token)){
        res.code(403).send({message: "errore di autenticazione1"})
        return;
      }

      let decoded;
      try{
        decoded = await verificaToken(token);
      }catch{
        res.code(403).send({message: "errore di autenticazione2"});
        return;
      }
      

      const file = req.params.key;
      //verifico se l'utente che fa richiesta è un admin
      if(decoded.admin){
        //se l'admin ha specificato un utente non modificherà i suoi file
        if(utente){
          const data = await leggiDisco('data/dati.json');

          const jsonData = JSON.parse(data);

          // Itera su ogni elemento del JSON e lo aggiunge all'array
          jsonData.forEach(element => {
            if(element.file === file && element.email === utente){
              element.contenuto = contenutoNuovo
            }
          });
          
          const updatedData = JSON.stringify(jsonData)

          await scriviDisco('data/dati.json', updatedData)
          res.code(200).send({message:"Dati aggiornati correttamente"})
          return;
        }
        //se non è stato specificato un utente vuol dire che l'admin vuole modificare un suo file
        
        const data = await leggiDisco('data/dati.json')
        
        const jsonData = JSON.parse(data);

        // Itera su ogni elemento del JSON e lo aggiunge all'array
        jsonData.forEach(element => {
          if(element.file === file && element.email === decoded.email){
            element.contenuto = contenutoNuovo
          }
        });
        
        const updatedData = JSON.stringify(jsonData)

        await scriviDisco('data/dati.json', updatedData)
        res.code(200).send({message:"Dati aggiornati correttamente"})
        return;
      }
      //se l'utente che fa richiesta di modifica non è un admin
      else{
        const data = await leggiDisco('data/dati.json')
        
        const jsonData = JSON.parse(data);

        // Itera su ogni elemento del JSON e lo aggiunge all'array
        jsonData.forEach(element => {
          if(element.file === file && element.email === decoded.email){
            element.contenuto = contenutoNuovo
          }
        });
        
        const updatedData = JSON.stringify(jsonData)
        await scriviDisco('data/dati.json', updatedData);
        res.code(200).send({message:"Dati aggiornati correttamente"})
        return;
        
      }
    })


    fastify.delete('/data/:key', async(req,res)=>{
      const token = req.body.token;
      const utente = req.body.email;

      if(rl.includes(token)){
        res.code(403).send({message: "errore di autenticazione1"})
        return;
      }

      let decoded;
      try{
        decoded = await verificaToken(token);
      }catch{
        res.code(403).send({message: "errore di autenticazione2"})
        return;
      }
      
        const file = req.params.key;
        //verifico se l'utente che fa richiesta è un admin
        if(decoded.admin){
          //se l'admin ha specificato un utente non eliminerà i suoi file
          if(utente){

            const data = await leggiDisco('data/dati.json');
            const jsonData = JSON.parse(data);

            let modificato = 0;
            jsonData.forEach((element,index) =>{
              if(element.email === utente && element.file === file){
                modificato = 1;
                jsonData.splice(index,1)
              }
            })

            if(modificato === 0){
              res.code(403).send({message:"Non ci sono file con questo nome"})
              return;
            }
            
            const updatedData = JSON.stringify(jsonData)
            await scriviDisco('data/dati.json', updatedData)
            res.code(200).send({message:"File eliminato correttamente"})
            return;
            
          }
          //se non è stato specificato un utente vuol dire che l'admin vuole eliminare un suo file
          else{
            const data = await leggiDisco('data/dati.json');

            const jsonData = JSON.parse(data);

            
            let modificato = 0;
            jsonData.forEach((element,index) =>{
              if(element.email === decoded.email && element.file === file){
                modificato = 1;
                jsonData.splice(index,1)
              }
            })
            if(modificato === 0){
              res.code(403).send({message:"Non ci sono file con questo nome"})
              return;
            }
 
            const updatedData = JSON.stringify(jsonData)
            await scriviDisco("data/dati.json", updatedData);
            res.code(200).send({message:"File eliminato correttamente"})
            return;

          }

        }
        //se l'utente che fa richiesta di DELETE non è un admin
        else{
          const data = await leggiDisco("data/dati.json");
          
          const jsonData = JSON.parse(data);

          let modificato = 0;
          jsonData.forEach((element,index) =>{
            if(element.email === decoded.email && element.file === file){
              modificato = 1;
              jsonData.splice(index,1)
            }
          })
          
          if(modificato === 0){
            res.code(403).send({message:"Non ci sono file con questo nome"})
            return;
          }

          const updatedData = JSON.stringify(jsonData)
          await scriviDisco("data/dati.json", updatedData);
          res.code(200).send({message:"File eliminato correttamente"})
          return;

        }

    })

  }



/*----------------------------------------COSE DA FARE PROGETTO--------------------------------------*/

/* SUPERUSER deve poter modificare tutto */ 
  
  module.exports = routes