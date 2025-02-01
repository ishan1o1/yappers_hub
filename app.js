
const express = require('express');
const app = express();
const userModel = require("./models/user");
const postModel = require("./models/post");

const crypto = require('crypto');
const jwtSecret = crypto.randomBytes(64).toString('hex');
const bcrypt = require('bcrypt'); 
const cookieParser = require('cookie-parser');  
const path = require('path');
const jwt = require('jsonwebtoken');
const multerconfig = require('./config/multerconfig');


app.set('view engine', 'ejs');  
app.use(express.static(path.join(__dirname, 'public')));    
app.use(express.urlencoded({ extended: false }));   
app.use(express.json());

app.use(cookieParser());


app.get('/', (req, res) => {
  res.render('index')
})

app.post('/register', async (req, res) => {
  let  {email, password , username , name , age} = req.body;
  let user = await userModel.findOne({email})
  if(user) return res.status(500).send("User already exists")
   
      bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(password, salt, async function(err, hash) {
          let user= await userModel.create({
            username,
            name,
           email,
           password:hash,
           age,
       })
      let token = jwt.sign({email:email, userid:user._id}, "shh");
      res.cookie("token", token)
       res.render('profile')
    })
      })
   })


app.get('/profile',isLoggedIn, async (req, res) => {
      let user = await userModel.findOne({email: req.user.email}).populate("posts")
      res.render('profile', {user})
   })

app.get('/like/:id',isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({_id: req.params.id}).populate("user")
    if(post.likes.indexOf(req.user.userid) === -1) 
    post.likes.push(req.user.userid)
  else
  post.likes.splice(post.likes.indexOf(req.user.userid), 1)
   
  await post.save()
    res.redirect('/profile')
 })

 app.get('/edit/:id',isLoggedIn, async (req, res) => {
  let post = await postModel.findOne({_id: req.params.id}).populate("user")
  
  res.render('edit', {post})
})

app.post('/update/:id',isLoggedIn, async (req, res) => {
  let post = await postModel.findOneAndUpdate({_id: req.params.id} , {content: req.body.content})
  
  res.redirect('/profile')
})

app.post('/post',isLoggedIn, async (req, res) => {
      let user = await userModel.findOne({email: req.user.email}) 
      let {content} = req.body; 
    let post = await postModel.create({
      user:user._id,
      content
     });

     user.posts.push(post._id)  
     await user.save()
     res.redirect('/profile')
   })

app.get('/login', (req, res) => {
  res.render('login')
})

app.post('/login', async (req, res) => {
let user = await userModel.findOne({email: req.body.email}) 
   if(!user){
    return res.send("Incorrect try again")
   }
   bcrypt.compare(req.body.password, user.password, function(err, result) {
       if(result){
        let token = jwt.sign({email: user.email},"shh");
        res.cookie("token", token)  
      res.redirect('/profile')
       }
      else
        res.redirect('/login')
      
    })
})

app.get('/logout', async (req, res) => {
      res.clearCookie('token');
      res.redirect('/');
})

function isLoggedIn(req, res, next){
  let token = req.cookies.token;
  if(!token) return res.redirect('/login')
    else{
      let data = jwt.verify(req.cookies.token , "shh")
      req.user = data;
    }
    next()
} 

app.listen(3000);
