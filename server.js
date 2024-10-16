require('dotenv').config(); 
const express= require('express'); 
const bcrypt= require('bcryptjs'); 
const jwt= require('jsonwebtoken');  
const db= require('./config'); 

const app= express(); 
app.use(express.json()); 

const JWT_SECRET= process.env.JWT_SECRET; 


//register user
app.post('/register', (req,res) => {
    const { username, password, email } = req.body;  
    if(!username || !password || !email) return res.status(400).send('All fields required!'); 
    
    const hashedPassword = bcrypt.hashSync(password, 8); 
    const query = 'INSERT INTO users(username, password, email) VALUES (?, ?, ?)'; 
    db.query(query, [username,hashedPassword,email], (err) => {
        if (err) return res.status(400).send('User already exists!'); 
        res.status(201).send('User Registered Successfully!'); 
    }); 
}); 


//login user and access/store refresh token in db 
app.post('/login', (req,res) => {
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).send('Username and Password Required!'); 

    const query= 'SELECT * FROM users WHERE username = ?'; 
    db.query(query, [username], (err, results) => {
        if (err || results.length === 0) return res.status(400).send('User not found!'); 

        const user= results[0]; 
        const passwordIsValid= bcrypt.compareSync(password,user.password); 
        if(!passwordIsValid) return res.status(401).send('Invalid Password!'); 

        const accessToken = jwt.sign({id: user.id}, JWT_SECRET, {expiresIn: '15m'}); 
        const refreshToken = jwt.sign({id: user.id}, JWT_SECRET, {expiresIn: '7d'}); 

        db.query('UPDATE users SET refresh_token= ? WHERE id= ?', [refreshToken, user.id], (err) => {
            if (err) 
                {
                    console.log(err);
                    return res.status(500).send('Failed to store the refreshed token!'); 
                }
                    res.status(200).send({ auth: true, accessToken, refreshToken}); 
        }); 
    }); 
}); 

//refresh token 
app.post('/token', (req,res) => {
    const { refreshToken } = req.body; 
    if (!refreshToken) return res.status(403).send('Refresh Token required'); 

    const query= 'SELECT * FROM users WHERE refresh_token= ?';  
    db.query(query, [refreshToken], (err, results) => {
        if (err || results.length ===0) return res.status(403).send('Invalid Refresh Token'); 

    const user= results[0]; 
    jwt.verify(refreshToken, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send('Invalid Refresh Token'); 

    const newAccessToken= jwt.sign({id: user.id}, JWT_SECRET, {expiresIn: '15m'}); 
      res.status(200).send({accessToken: newAccessToken}); 

        }); 
    }); 
}); 

//profile authorization 
app.get('/profile', verifyToken, (req,res) => {
    res.status(200).send('Protected route!'); 
}); 

function verifyToken(req,res,next) 
{
    const authHeader= req.headers['authorization']; 
    if (!authHeader) {
        return res.status(403).send('No Token provided!');
    }

    const token = authHeader.split(' ')[1]; 
    
    if(!token) return res.status(403).send('No Token provided!'); 
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(500).send('Failed to authenticate Token'); 
        }
            req.userId= decoded.id; 
        next();  
    });
}

app.listen(3000, () =>
console.log('Server running on http://localhost:3000')); 

