const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User.js');
const Place = require('./models/Place.js');
const Booking = require('./models/Booking.js');
const cookieParser = require('cookie-parser');
const imageDownloader = require('image-downloader');
const {S3Client, PutObjectCommand} = require('@aws-sdk/client-s3');
const multer = require('multer');
const fs = require('fs');
const mime = require('mime-types');

require('dotenv').config();
const app = express();

// CORS FIRST!
app.use(cors({
  credentials: true,
  origin: [
    'https://house-rent-f.vercel.app',
    'http://localhost:5173',
    'http://127.0.0.1:5173'
  ],
}));

// Ensure uploads directory exists
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname+'/uploads'));

async function uploadToS3(path, originalFilename, mimetype) {
  const client = new S3Client({
    region: 'us-east-1',
    credentials: {
      accessKeyId: process.env.S3_ACCESS_KEY,
      secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
    },
  });
  const parts = originalFilename.split('.');
  const ext = parts[parts.length - 1];
  const newFilename = Date.now() + '.' + ext;
  await client.send(new PutObjectCommand({
    Bucket: bucket,
    Body: fs.readFileSync(path),
    Key: newFilename,
    ContentType: mimetype,
    ACL: 'public-read',
  }));
  return `https://${bucket}.s3.amazonaws.com/${newFilename}`;
}

function getUserDataFromReq(req) {
  return new Promise((resolve, reject) => {
    jwt.verify(req.cookies.token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      resolve(userData);
    });
  });
}

// Seed admin user if not exists
async function seedAdmin() {
  const adminEmail = 'mohamett@gmail.com';
  const adminExists = await User.findOne({ email: adminEmail });
  if (!adminExists) {
    await User.create({
      name: 'mohamet',
      email: adminEmail,
      password: bcrypt.hashSync('12345678', bcryptSalt),
      role: 'admin',
    });
    console.log('Admin user seeded.');
  }
}
seedAdmin();

app.get('/api/test', (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  res.json('test ok');
});

app.post('/api/register', async (req,res) => {
  const {name,email,password,role} = req.body;
  try {
    const userDoc = await User.create({
      name,
      email,
      password:bcrypt.hashSync(password, bcryptSalt),
      role: role || 'user',
    });
    res.json(userDoc);
  } catch (e) {
    res.status(422).json(e);
  }
});

app.post('/api/login', async (req,res) => {
  const {email,password} = req.body;
  const userDoc = await User.findOne({email});
  if (userDoc) {
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (passOk) {
      jwt.sign({
        email:userDoc.email,
        id:userDoc._id,
        role:userDoc.role
      }, jwtSecret, {}, (err,token) => {
        if (err) throw err;
        res.cookie('token', token).json({
          _id: userDoc._id,
          name: userDoc.name,
          email: userDoc.email,
          role: userDoc.role
        });
      });
    } else {
      res.status(422).json('pass not ok');
    }
  } else {
    res.json('not found');
  }
});

app.get('/api/profile', (req,res) => {
  const {token} = req.cookies;
  if (token) {
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      const user = await User.findById(userData.id);
      res.json({name:user.name, email:user.email, _id:user._id, role:user.role});
    });
  } else {
    res.json(null);
  }
});

app.post('/api/logout', (req,res) => {
  res.cookie('token', '').json(true);
});


app.post('/api/upload-by-link', async (req,res) => {
  const {link} = req.body;
  const newName = 'photo' + Date.now() + '.jpg';
  await imageDownloader.image({
    url: link,
    dest: '/tmp/' +newName,
  });
  const url = await uploadToS3('/tmp/' +newName, newName, mime.lookup('/tmp/' +newName));
  res.json(url);
});

// Update multer to use uploads/ and 10MB file size limit
const photosMiddleware = multer({ dest: uploadDir + '/', limits: { fileSize: 10 * 1024 * 1024 } });
// Update /api/upload to use local file path only
app.post('/api/upload', photosMiddleware.array('photos', 100), async (req,res) => {
  const uploadedFiles = [];
  for (let i = 0; i < req.files.length; i++) {
    const { path, originalname } = req.files[i];
    // Just return the local file path (relative to uploads/)
    uploadedFiles.push('/' + path.replace('uploads', 'uploads').replace('\\', '/'));
  }
  res.json(uploadedFiles);
});

app.post('/api/places', (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  const {token} = req.cookies;
  const {
    title,address,addedPhotos,description,price,
    perks,extraInfo,checkIn,checkOut,maxGuests,
  } = req.body;
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) throw err;
    const placeDoc = await Place.create({
      owner:userData.id,price,
      title,address,photos:addedPhotos,description,
      perks,extraInfo,checkIn,checkOut,maxGuests,
    });
    res.json(placeDoc);
  });
});

app.get('/api/user-places', (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  const {token} = req.cookies;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: JWT must be provided' });
  }
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    const {id} = userData;
    res.json( await Place.find({owner:id}) );
  });
});

app.get('/api/places/:id', async (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  const {id} = req.params;
  res.json(await Place.findById(id));
});

app.put('/api/places', async (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  const {token} = req.cookies;
  const {
    id, title,address,addedPhotos,description,
    perks,extraInfo,checkIn,checkOut,maxGuests,price,
  } = req.body;
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) throw err;
    const placeDoc = await Place.findById(id);
    if (userData.id === placeDoc.owner.toString()) {
      placeDoc.set({
        title,address,photos:addedPhotos,description,
        perks,extraInfo,checkIn,checkOut,maxGuests,price,
      });
      await placeDoc.save();
      res.json('ok');
    }
  });
});

app.get('/api/places', async (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  res.json( await Place.find() );
});

app.post('/api/bookings', async (req, res) => {
  mongoose.connect(process.env.MONGO_URL);
  const userData = await getUserDataFromReq(req);
  const {
    place,checkIn,checkOut,numberOfGuests,name,phone,price,
  } = req.body;
  Booking.create({
    place,checkIn,checkOut,numberOfGuests,name,phone,price,
    user:userData.id,
  }).then((doc) => {
    res.json(doc);
  }).catch((err) => {
    throw err;
  });
});



app.get('/api/bookings', async (req,res) => {
  mongoose.connect(process.env.MONGO_URL);
  const userData = await getUserDataFromReq(req);
  res.json( await Booking.find({user:userData.id}).populate('place') );
});

// Admin-only: Get all users
app.get('/api/users', async (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    const adminUser = await User.findById(userData.id);
    if (!adminUser || adminUser.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const users = await User.find({}, '-password'); // Exclude password
    res.json(users);
  });
});

// Admin-only: Update user info
app.put('/api/users/:id', async (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    const adminUser = await User.findById(userData.id);
    if (!adminUser || adminUser.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const { name, email, role } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.name = name;
    user.email = email;
    user.role = role;
    await user.save();
    res.json({ success: true });
  });
});

// Admin-only: Delete user
app.delete('/api/users/:id', async (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    const adminUser = await User.findById(userData.id);
    if (!adminUser || adminUser.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await user.deleteOne();
    res.json({ success: true });
  });
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
