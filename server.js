const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const session = require('express-session');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
const port = 3000;

// Connection URL and Database Name
const url = 'mongodb+srv://BahayParesDB:chkBX4BzDXvScktM@cluster0.dzsyavl.mongodb.net/'; // Replace with your MongoDB connection URL
const dbName = 'BahayParesDB'; // Replace with your database name
const collectionName = 'UserAccounts'; // Replace with your collection name
const collectionAdmin = 'AdminAccounts'; //Admin
const collectionSuperAdmin = 'SuperAdmin'; //Admin
const collectionMenu = 'MenuList'; //Menu


const storage = multer.memoryStorage(); // Use memory storage for file uploads
const upload = multer({
  storage: storage
});

app.use(bodyParser.json());


const options = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
};

const mongoClient = new MongoClient(url, options);

(async () => {
  const client = await mongoClient.connect();
  const db = client.db(dbName);
  const collection = db.collection(collectionMenu);

  // Create an index on the "category" field
  await collection.createIndex({ category: 1 });

  client.close();
})();

let db;

async function connectToDatabase() {
  const client = await MongoClient.connect(url, options);
  db = client.db(dbName);
}

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

app.use(express.static(path.join(__dirname, 'public')))

const MongoDBStore = require('connect-mongodb-session')(session);

const store = new MongoDBStore({
  uri: url,
  databaseName: dbName,
  collection: 'sessions',
});

store.on('error', function (error) {
  console.error('Session store error:', error);
});

app.use(
  session({
    secret: '@BahayParesTapsihanDasma01',
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
      maxAge: 3600000, //Expire in 1 hour
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  async (email, password, done) => {
    try {
        // Check if the user is a super admin
        const superAdminAccount = await db.collection(collectionSuperAdmin).findOne({ email });

        if (superAdminAccount) {
          const isPasswordMatch = await bcrypt.compare(password, superAdminAccount.password);
          if (isPasswordMatch) {
            console.log('Super Admin login successful:', superAdminAccount);
            return done(null, { ...superAdminAccount, isSuperAdmin: true });
          } else {
            console.log('Incorrect password for the super admin account.');
            return done(null, false, { message: 'Incorrect password' });
          }
      } else {
        // Check if the user is an admin
        const adminAccount = await db.collection(collectionAdmin).findOne({ email });

        if (adminAccount) {                            
          const isPasswordMatch = await bcrypt.compare(password, adminAccount.password);
          if (isPasswordMatch) {
            console.log('Admin login successful:', adminAccount);
            return done(null, { ...adminAccount, isAdmin: true });
          } else {
            console.log('Incorrect password for the admin account.');
            return done(null, false, { message: 'Incorrect password' });
          }
        } else {
          // If not an admin, check the regular user collection
          const userAccount = await db.collection(collectionName).findOne({ email });
        
          if (userAccount) {
            if (userAccount.verified) {
              const isPasswordMatch = await bcrypt.compare(password, userAccount.password);
              if (isPasswordMatch) {
                console.log('User login successful:', userAccount);
                return done(null, userAccount);
              } else {
                const errorMessage = 'Incorrect password for the user account.';
                return done(null, false, { message: errorMessage });
              }
            } else {
              const errorMessage = 'User is not yet verified.';
              return done(null, false, { message: errorMessage });
            }
          } else {
            const errorMessage = 'No account found with the provided email.';
            return done(null, false, { message: errorMessage });
          }
        }               
      }
    } catch (err) {
      console.error('Error during login:', err);
      return done(err);
    }
  }
));


passport.serializeUser((user, done) => {
  done(null, user); // Serialize the entire user object
});

passport.deserializeUser((user, done) => {
  done(null, user); // Deserialize the entire user object
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next(); // User is authenticated, proceed to the next middleware
  }
  
  // Redirect to the login page with a message
  res.redirect('/?message=Please login to access this page'); 
}

const roleAccess = {
  Cashier: {
    allowedURLs: ['/Updateorder', '/OrderHistory'],
  },
  KitchenPersonnel: {
    allowedURLs: ['/Updateorder', '/menucustomization'],
  },
  DeliveryPerson: {
    allowedURLs: ['/Updateorder'],
  },
  isSuperAdmin: {
    allowedURLs: ['/Updateorder', '/menucustomization', '/OrderHistory', '/superadmin'],
  },
};

function roleBasedAccess(req, res, next) {
  const userRole = req.user && req.user.isSuperAdmin ? 'isSuperAdmin' : req.user && req.user.userType;
  const requestedURL = req.originalUrl;

  if (roleAccess[userRole] && roleAccess[userRole].allowedURLs.includes(requestedURL)) {
    next(); // User is allowed to access this URL
  } else {
    // Show an alert dialog to the user
    res.send(`
  <script>
    alert("Sorry, your account does not have permission to access this page. If you believe this is an error or if you need access to this page, please contact our support team for assistance.\\n\\nContact Support:\\n\\nEmail: support@yourwebsite.com\\nPhone: +1-800-123-4567\\n\\nThank you for your understanding.");
    history.back();
  </script>
`);

  }
}


app.get('/', (req, res) => {
  const message = req.query.message || ''; // Get the message from the query string
  res.sendFile(path.join(__dirname, '/views/index.html'));
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ message: 'Logout error' });
    }
    
    // Optionally, you can add a logout message to the session
    req.session.logoutMessage = 'You have been logged out successfully.';
    
    res.status(200).json({
      message: 'Logout successful',
    });
  });
});

app.get('/check-auth', (req, res) => {
  if (req.isAuthenticated()) {
    // User is authenticated
    res.json({ isAuthenticated: true });
  } else {
    // User is not authenticated
    res.json({ isAuthenticated: false });
  }
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/register.html'));
});

app.get('/policy', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/policy.html'));
});

app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/termsandcondition.html'));
});

app.get('/resetPassword', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/resetPassword.html'));
});

app.get('/menu', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/menu.html'));
});

app.get('/ContactUs', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/ContactUs.html'));
});

app.get('/AboutUs', (req, res) => {
  res.sendFile(path.join(__dirname, '/views/AboutUs.html'));
});

app.get('/superadmin', isAuthenticated, roleBasedAccess, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/superadmin.html'));
});

app.get('/transactionpage.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/transactionpage.html'));
});

app.get('/Vieworder', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/ViewOrderStatus.html'));
});

app.get('/Updateorder', isAuthenticated, roleBasedAccess, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/UpdateOrderStatus.html'));
});

app.get('/menucustomization', isAuthenticated, roleBasedAccess, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/menucustomization.html'));
});

app.get('/OrderHistory', isAuthenticated, roleBasedAccess, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/OrderHistory.html'));
});

app.get('/Profile', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '/views/Profile.html'));
});

app.use(async (req, res, next) => {
  if (!db) {
    try {
      const client = await MongoClient.connect(url, options);
      db = client.db(dbName);
      req.db = db; // Attach the database instance to the request object
    } catch (err) {
      console.error('Error connecting to MongoDB:', err);
      return res.status(500).send('Internal Server Error');
    }
  } else {
    req.db = db; // Attach the existing database instance to the request object
  }
  next();
});

app.post('/login', passport.authenticate('local'), (req, res) => {
  // This route will only be reached if authentication is successful
  let redirectTo = '/menu'; // Default redirection for regular users

  if (req.user.isSuperAdmin) {
    redirectTo = '/superadmin'; // Redirect admin users to /superadmin
  }

  if (req.user.isAdmin) {
    redirectTo = '/Updateorder'; // Redirect admin users to /Updateorder
  }

  res.status(200).json({
    message: 'Login successful',  
    username: req.user.username,
    user: req.user,
    redirectTo: redirectTo // Use the appropriate redirection based on user role
  });
});

  


// Insert route
app.post('/insert', async (req, res) => {
  const {
    username,
    email,
    password,
    userId,
    phone
  } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const existingUser = await db.collection(collectionName).findOne({
      $or: [
        { username },
        { email },
        { phone }
      ]
    });

    if (existingUser) {
      console.log('User with the same username or email already exists.');
      return res.status(400).json({
        error: 'A user with the same username or email already exists.'
      });
    }

    // Hash the password using bcrypt
    const hashedPassword = await hashPassword(password);

    // Generate a random verification token (you can use a library like `crypto` for this)
    const verificationToken = generateRandomToken(32); // You can choose your desired token length

    // Store the verification token in the database along with a timestamp for expiration
    await db.collection(collectionName).insertOne({
      username,
      email,
      password: hashedPassword,
      userId,
      phone,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 60 * 60 * 1000, // 24 hours validity
      verified: false, // Set initially to false
    });

    // Send an email to the user with a verification link that includes the token
    const verificationLink = "https://congenial-space-eureka-v6v57qjg5g473p56x-3000.app.github.dev/verify?token=" + verificationToken;
    sendVerificationEmail(email, verificationLink);

    res.status(201).json({
      message: 'Registered successfully! Check your email for verification.'
    });
  } catch (err) {
    console.error('Error registering:', err);
    res.status(500).json({
      error: 'An error occurred while registering.'
    });
  }
});

function generateRandomToken(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return token;
}


app.get('/verify', async (req, res) => {
  const verificationToken = req.query.token;
  let message;

  try {
    const user = await db.collection(collectionName).findOne({ verificationToken });

    if (!user) {
      // Handle invalid or expired verification tokens
      message = 'Invalid or expired verification token.';
    } else if (user.verified) {
      // If the user is already verified, display a message
      message = 'Your email has already been verified. You can now log in.';
    } else if (user.verificationTokenExpires < Date.now()) {
      message = 'Verification token has expired.';
    } else {
      // Mark the user as verified and remove the verification token
      await db.collection(collectionName).updateOne(
        { verificationToken },
        { $set: { verified: true }, $unset: { verificationToken: 1, verificationTokenExpires: 1 } }
      );

      message = 'Your email has been successfully verified. You can now log in.';
    }

    // Redirect to the home page with the message parameter in the URL
    res.redirect(`/?message=${message}`);
  } catch (err) {
    // Handle any errors that may occur during the verification process
    console.error('Error verifying email:', err);
    message = 'An error occurred during email verification.';
    res.redirect(`/?message=${message}`);
  }
});

// Create a nodemailer transporter with your email service provider's credentials
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'bahayparestapsihandasma@gmail.com',
    pass: 'bcmn hpvw tbhm dfcn'
  }
});

app.post('/sendorderemail', async (req, res) => {
  try {
    const { userId, orderId, items, location, discount, totalprice, paymentmethod, deliverystatus, specialinstruction } = req.body;

    const emailContent = `
          <h1>New Order Received</h1>
          <h2>Order Details:</h2>
          <p><strong>User ID:</strong> ${userId}</p>
          <p><strong>Order ID:</strong> ${orderId}</p>
          <h3>Order:</h3>
          <ul>
            ${items.map(
              (item) => `
                <li>
                  <p><strong>Item Name:</strong> ${item.name}</p>
                  <p><strong>Quantity:</strong> ${item.quantity}</p>
                </li>
              `
            ).join('')}
          </ul>
          <h3>Location: ${location}</h3>
          <h3>Discount:</h3>
          <ul>
            <li><strong>Selected Discount:</strong> ${discount.SelectedDiscount}</li>
            <li><strong>Card Name:</strong> ${discount.CardName}</li>
            <li><strong>Card ID:</strong> ${discount.CardId}</li>
            <li><strong>Customer Discount:</strong> ${discount.CustomerDiscount}</li>
          </ul>
          <h3>Total Price:</h3>
          <ul>
            <li><strong>Subtotal:</strong> ${totalprice.Subtotal}</li>
            <li><strong>Delivery Fee:</strong> ${totalprice.DeliveryFee}</li>
            <li><strong>Discount:</strong> ${totalprice.Discount}</li>
            <li><strong>Total:</strong> ${totalprice.Total}</li>
          </ul>
          <p><strong>Payment Method:</strong> ${paymentmethod}</p>
          <p><strong>Delivery Status:</strong> ${deliverystatus}</p>
          <h3>Special Instruction: ${specialinstruction}</h3>
    `;

    // Create the email message
    const mailOptions = {
      from: 'bahayparestapsihandasma@gmail.com',
      to: 'davidgalolo56@gmail.com', // Replace with the staff's email address
      subject: 'New Order Received',
      html: emailContent
    };

    // Send the email
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error(error);
  }
});

function sendVerificationEmail(email, verificationLink) {
  const mailOptions = {
    from: 'bahayparestapsihandasma@gmail.com',
    to: email,
    subject: 'Email Verification',
    html: `<p>Thank you for signing up to Bahay Pares Tapsihan! To complete your registration, please click the verification link below:</p>
    <p><a href="${verificationLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify My Email</a></p>
    `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
}


app.post('/insertAdmin', async (req, res) => {
  const {
    username,
    email,
    password,
    userType
  } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Check if a user with the same username or email already exists
    const existingUser = await db.collection(collectionAdmin).findOne({
      $or: [{
        username
      }, {
        email
      }]
    });

    if (existingUser) {
      console.log('User with the same username or email already exists.');
      return res.status(400).json({
        error: 'A user with the same username or email already exists.'
      });
    }

    // Hash the password using bcrypt
    const hashedPassword = await hashPassword(password);

    // Store the hashed password in the database
    await db.collection(collectionAdmin).insertOne({
      username,
      email,
      password: hashedPassword, // Store the hashed password
      userType,
    });

    console.log('Record inserted successfully!');
    res.status(201).json({
      message: 'Record inserted successfully!'
    });
  } catch (err) {
    console.error('Error inserting record:', err);
    res.status(500).json({
      error: 'An error occurred while inserting the record.'
    });
  }
});

// Function to hash a password using bcrypt
async function hashPassword(password) {
  try {
    const saltRounds = 10; // Number of salt rounds, you can adjust this value
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    console.error('Error hashing password:', error);
    throw error; // Rethrow the error for better debugging
  }
}


app.post('/insertmenu', upload.single('image'), async (req, res) => {
  const {
    category,
    name,
    description,
    price,
    availability
  } = req.body;
  const imageBuffer = req.file.buffer; // Get the uploaded image as a buffer

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Convert 'price' to a float and 'availability' to a boolean
    const parsedPrice = parseFloat(price);
    const parsedAvailability = availability === 'true';

    // Define the default status value (you can change this to whatever default status you prefer)
    const defaultStatus = 'normal';

    // Insert the menu item with the image buffer into MongoDB
    await db.collection(collectionMenu).insertOne({
      category,
      name,
      description, // Include description in the database entry
      price: parsedPrice,
      availability: parsedAvailability,
      status: defaultStatus, // Set the default status
      image: imageBuffer.toString('base64'), // Store image as base64 string
    });

    console.log('Record inserted successfully!');
    res.status(201).json({
      message: 'Record inserted successfully!'
    });
  } catch (err) {
    console.error('Error inserting record:', err);
    res.status(500).json({
      error: 'An error occurred while inserting the record.'
    });
  }
});

app.get('/fetchAllItems', async (req, res) => {
  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({ error: 'Database connection is not ready.' });
    }

    // Fetch all items from the 'MenuList' collection in alphabetical order by category
    const allItems = await db.collection(collectionMenu).find({}).sort({ name: 1 }).toArray();

    // Send the sorted list of items as JSON response
    res.status(200).json(allItems);
  } catch (err) {
    console.error('Error fetching all items:', err);
    res.status(500).json({ error: 'An error occurred while fetching all items.' });
  }
});

app.get('/getMenuItem/:category/:name', async (req, res) => {
  const category = req.params.category;
  const name = req.params.name;

  try {
      if (!db) {
          console.log('Database connection is not established yet.');
          return res.status(500).json({ error: 'Database connection is not ready.' });
      }

      const menuItem = await db.collection(collectionMenu).findOne({
        name: name,  // Use the 'name' variable
    category: category,  // Use the 'category' variable
    });
    
      if (menuItem) {
          // Send the menu item as JSON response
          res.status(200).json(menuItem);
      } else {
          console.log('No document found with the provided name.');
          res.status(404).json({ error: 'No menu item found with the provided name.' });
      }
  } catch (err) {
      console.error('Error fetching menu item for editing:', err);
      res.status(500).json({ error: 'An error occurred while fetching the menu item.' });
  }
});



app.post('/updatemenuItem', upload.single('image'), async (req, res) => {
  const {
      category,
      name,
      newCategory, // Add newCategory parameter to accept the new category
      newName,
      description,
      price,
      availability,
      status
  } = req.body;

  // Check if a new image is provided
  const imageBuffer = req.file ? req.file.buffer : null;

  try {
      if (!db) {
          console.log('Database connection is not established yet.');
          return res.status(500).json({
              error: 'Database connection is not ready.'
          });
      }

      // Check if a menu item with the new name and category already exists
      const existingItem = await db.collection(collectionMenu).findOne({
          name: newName,
          category: newCategory // Use the newCategory parameter
      });

      if (existingItem && existingItem.name !== name) {
          console.log('A menu item with the new name and category already exists.');
          return res.status(400).json({
              error: 'A menu item with the new name and category already exists.'
          });
      }

      // Convert 'price' to a float and 'availability' to a boolean
      const parsedPrice = parseFloat(price);
      const parsedAvailability = availability === 'true';

      // Create an update object with the provided values
      const updateValues = {
          $set: {
              category: newCategory, // Update the category with newCategory
              name: newName,
              description,
              price: parsedPrice,
              availability: parsedAvailability,
              status
          },
      };

      // Include the image in the update if a new image is provided
      if (imageBuffer) {
          updateValues.$set.image = imageBuffer.toString('base64');
      }

      // Find the menu item with the original name and update it
      const result = await db.collection(collectionMenu).updateOne({
          name,
          category
      }, updateValues);

      if (result.matchedCount > 0) {
          console.log('Menu item updated successfully.');
          res.status(200).json({
              message: 'Menu item updated successfully!'
          });
      } else {
          console.log('No menu item found with the provided name.');
          res.status(404).json({
              error: 'No menu item found with the provided name.'
          });
      }
  } catch (err) {
      console.error('Error updating menu item:', err);
      res.status(500).json({
          error: 'An error occurred while updating the menu item.'
      });
  }
});

app.post('/updatemenu', async (req, res) => {
  const {
    name,
    availability
  } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const updateQuery = {
      name
    };
    const updateValues = {
      $set: {
        availability
      }
    };

    const result = await db.collection('MenuList').updateOne(updateQuery, updateValues);

    if (result.matchedCount > 0) {
      console.log('Document updated successfully.');
      res.status(200).json({
        message: 'Document updated successfully!'
      });
    } else {
      console.log('No document found with the provided menu.');
      res.status(404).json({
        error: 'No document found with the provided menu.'
      });
    }
  } catch (err) {
    console.error('Error updating document:', err);
    res.status(500).json({
      error: 'An error occurred while updating the document.'
    });
  }
});

app.delete('/deleteOrder/:name', async (req, res) => {
  const {
    name
  } = req.params;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Delete the order from MongoDB
    const result = await db.collection('MenuList').deleteOne({
      name
    });

    if (result.deletedCount === 0) {
      console.log('No menu found with the provided name.');
      return res.status(404).json({
        error: 'No menu found with the provided name.'
      });
    }

    console.log('Menu deleted successfully.');
    res.status(200).json({
      message: 'Menu deleted successfully.'
    });
  } catch (err) {
    console.error('Error deleting menu from MongoDB:', err);
    res.status(500).json({
      error: 'An error occurred while deleting the menu.'
    });
  }
});

app.get('/getUserByUserName', async (req, res) => {
  const {
    username
  } = req.query;
  
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Search for the user with the provided username
    const user = await db.collection(collectionName).findOne({
      username
    });

    if (user) {
      // Extract the userId
      const userId = user.userId;

      console.log(`User found with username ${username}, userId: ${userId}`);
      res.status(200).json({
        userId
      });
    } else {
      console.log(`No user found with username ${username}.`);
      res.status(404).json({
        error: 'No user found with the provided username.'
      });
    }
  } catch (err) {
    console.error('Error searching for user by username:', err);
    res.status(500).json({
      error: 'An error occurred while searching for the user.'
    });
  }
});

app.post('/forgotpassword', async (req, res) => {
  const {
    usernameOrEmail,
    resetToken, // Get the token from the frontend request
  } = req.body;

  try {
    // Check if the user with the provided username or email exists in your database
    const user = await db.collection(collectionName).findOne({
      $or: [{
        username: usernameOrEmail
      }, {
        email: usernameOrEmail
      }],
    });

    if (user) {
      // Use the provided resetToken in the database
      await db.collection('ResetPassword').insertOne({
          token: resetToken,
          userId: user.userId,
          username: user.username,
      });

      // Send an email with the resetToken
      await sendResetEmail(user.email, resetToken); // Call sendResetEmail function

      console.log('Password reset initiated for user:', user.username);
      return res.status(200).json({
          message: 'Password reset initiated',
          resetToken: resetToken, // Include the same resetToken in the response
      });
    } else {
      console.log('User not found with the provided username/email:', usernameOrEmail);
      return res.status(404).json({
        error: 'User not found'
      });
    }
  } catch (error) {
    console.error('Error initiating password reset:', error);
    return res.status(500).json({
      error: 'An error occurred while initiating password reset'
    });
  }
});

app.post('/resetPassword', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
      // Verify the token in the "ResetPassword" collection
      const resetData = await db.collection('ResetPassword').findOne({ token });

      if (resetData) {
          // Fetch the user associated with the token
          const user = await db.collection('UserAccounts').findOne({ userId: resetData.userId });

          if (user) {
              // Hash the new password before updating it
              const hashedPassword = await bcrypt.hash(newPassword, 10);

              // Update the user's password in your database
              await db.collection('UserAccounts').updateOne(
                  { userId: user.userId },
                  {
                      $set: {
                          password: hashedPassword // Store the hashed password
                      }
                  }
              );

              // Clear or invalidate the token (optional, you can remove the token from the "ResetPassword" collection)
              await db.collection('ResetPassword').deleteOne({ token });

              console.log('Password reset successful for user:', user.username);
              return res.status(200).json({ message: 'Password reset successful' });
          } else {
              console.log('User not found for the token:', token);
              return res.status(404).json({ error: 'User not found' });
          }
      } else {
          console.log('Token not found:', token);
          return res.status(404).json({ error: 'Token not found' });
      }
  } catch (error) {
      console.error('Error resetting password:', error);
      return res.status(500).json({ error: 'An error occurred while resetting the password' });
  }
});

// Add this route to store the reset token in the "ResetPassword" collection
app.post('/storeResetToken', async (req, res) => {
  const { token, username } = req.body;

  try {
      // Store the reset token in the "ResetPassword" collection
      await db.collection('ResetPassword').insertOne({
          token: token,
          username: username,
      });

      console.log('Reset token stored successfully for user:', username);
      return res.status(200).json({ message: 'Reset token stored' });
  } catch (error) {
      console.error('Error storing reset token:', error);
      return res.status(500).json({ error: 'An error occurred while storing the reset token' });
  }
});

async function sendResetEmail(email, resetToken) {
  try {
    // Create a nodemailer transporter with your email service settings
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'bahayparestapsihandasma@gmail.com',
        pass: 'bcmn hpvw tbhm dfcn'
      },
    });

    // Compose email message
    const mailOptions = {
      from: 'bahayparestapsihandasma@gmail.com',
      to: email,
      subject: 'Bahay Pares Tapsihan Password Reset Request',
      html: `
        <html>
          <body>
            <p>You have requested a password reset for your Bahay Pares Tapsihan account. To reset your password, please click the button below:</p>
            <a href="https://congenial-space-eureka-v6v57qjg5g473p56x-3000.app.github.dev/resetPassword?token=${resetToken}">
              <button style="background-color: #007BFF; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">Reset Password</button>
            </a>
            <p>If you did not request this password reset, please ignore this email. Your account's security is important to us.</p>
            <p>Thank you for using Bahay Pares Tapsihan.</p>
          </body>
        </html>
      `,
    };

    // Send the email
    const info = await transporter.sendMail(mailOptions);
    console.log('Password reset email sent:', info.response);
  } catch (error) {
    console.error('Error sending password reset email:', error);
    throw error; // Rethrow the error for better debugging
  }
}

app.post('/verifyToken', async (req, res) => {
  const { token } = req.body;

  try {
      // Verify the token in the "ResetPassword" collection
      const resetData = await db.collection('ResetPassword').findOne({ token });

      if (resetData) {
          return res.status(200).json({ message: 'Token verified' });
      } else {
          return res.status(401).json({ error: 'Token not verified' });
      }
  } catch (error) {
      console.error('Error verifying token:', error);
      return res.status(500).json({ error: 'An error occurred while verifying the token' });
  }
});


app.post('/updateDeliveryStatus', async (req, res) => {
  const {
    orderId,
    deliverystatus
  } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const updateQuery = {
      orderId
    };
    const updateValues = {
      $set: {
        deliverystatus
      }
    };

    const result = await db.collection('OrderStatus').updateOne(updateQuery, updateValues);

    if (result.matchedCount > 0) {
      console.log('Delivery status updated successfully.');
      res.status(200).json({
        message: 'Delivery status updated successfully!'
      });
    } else {
      console.log('No order found with the provided orderId.');
      res.status(404).json({
        error: 'No order found with the provided orderId.'
      });
    }
  } catch (err) {
    console.error('Error updating delivery status:', err);
    res.status(500).json({
      error: 'An error occurred while updating the delivery status.'
    });
  }
});

app.post('/cancelOrder', async (req, res) => {
  const { orderId } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const cancelQuery = {
      orderId,
      deliverystatus: { $nin: ['Out for delivery', 'Delivered'] } // Ensure the order is not in these states
    };

    const cancelResult = await db.collection('OrderStatus').deleteOne(cancelQuery);

    if (cancelResult.deletedCount > 0) {
      console.log('Order canceled successfully.');
      res.status(200).json({
        message: 'Order canceled successfully!'
      });
    } else {
      console.log('No order found with the provided orderId or the order is already "Delivering" or "Delivered."');
      res.status(404).json({
        error: 'No order found with the provided orderId or the order is already "Delivering" or "Delivered."'
      });
    }
  } catch (err) {
    console.error('Error canceling order:', err);
    res.status(500).json({
      error: 'An error occurred while canceling the order.'
    });
  }
});

// Insert route
app.post('/insertcomments', async (req, res) => {
  const {
    fname,
    lname,
    email,
    message
  } = req.body;
  console.log('Received request body:', req.body);

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    await db.collection('CustomerFeedback').insertOne({
      fname,
      lname,
      email,
      message
    });

    console.log('Feeback messaged successfully!');
    res.status(201).json({
      message: 'Feeback messaged successfully!'
    });
  } catch (err) {
    console.error('Error inserting record:', err);
    res.status(500).json({
      error: 'An error occurred while inserting the record.'
    });
  }
});

app.get('/admin', async (req, res) => {

  try {

    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const data = await db.collection(collectionAdmin).find({
    }).toArray();

    res.status(200).json(data);
  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
  
});

app.post('/updateSuperAdmin', async (req, res) => {
  const { oldSuperEmail, oldSuperPassword, updateOption, newSuperEmail, newSuperPassword } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    if (!oldSuperEmail || !oldSuperPassword || !updateOption) {
      console.log('Missing required fields:', oldSuperEmail, oldSuperPassword, updateOption);
      return res.status(400).json({
        message: 'Please provide old email, old password, and update option.'
      });
    }

    // Verify the old email before proceeding with the update
    const superAdmin = await db.collection(collectionSuperAdmin).findOne({ email: oldSuperEmail });

    if (!superAdmin) {
      console.log('Super admin not found with provided email:', oldSuperEmail);
      return res.status(404).json({
        error: 'Super admin account with the provided old email not found.'
      });
    }

    // Compare old password hash
    const isPasswordMatch = await bcrypt.compare(oldSuperPassword, superAdmin.password);

    if (!isPasswordMatch) {
      console.log('Old password does not match:');
      return res.status(401).json({
        error: 'Old password does not match.'
      });
    }

    let result;
    if (updateOption === 'newEmail') {
      if (!newSuperEmail) {
        console.log('New email not provided for update.');
        return res.status(400).json({
          message: 'Please provide the new email for the update.'
        });
      }

      result = await db.collection(collectionSuperAdmin).updateOne(
        { email: oldSuperEmail },
        {
          $set: { email: newSuperEmail }
        }
      );
    } else if (updateOption === 'newPassword') {
      if (!newSuperPassword) {
        console.log('New password not provided for update.');
        return res.status(400).json({
          message: 'Please provide the new password for the update.'
        });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newSuperPassword, 10);

      result = await db.collection(collectionSuperAdmin).updateOne(
        { email: oldSuperEmail },
        {
          $set: { password: hashedPassword }
        }
      );
    }

    if (result.matchedCount > 0) {
      console.log('Super admin account updated successfully.');
      res.status(200).json({
        message: 'Super admin account updated successfully!'
      });
    } else {
      console.log('No super admin account found with the provided old email.');
      res.status(404).json({
        error: 'No super admin account found with the provided old email.'
      });
    }
  } catch (err) {
    console.error('Error updating super admin account:', err);
    res.status(500).json({
      error: 'An error occurred while updating the super admin account.'
    });
  }
});


app.get('/adminfetch', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch data from MongoDB
    const data = await db.collection('OrderStatus').find({}).toArray();

    // Send the data as JSON response
    res.status(200).json(data);

  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/menufetch', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch data from MongoDB
    const data = await db.collection('MenuList').find({}).toArray();

    // Send the data as JSON response
    res.status(200).json(data);

  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/featuredmenu', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch data from MongoDB where 'status' is 'featured'
    const data = await db.collection('MenuList').find({ status: 'featured' }).toArray();

    // Send the data as JSON response
    res.status(200).json(data);

  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/salemenu', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch data from MongoDB where 'status' is 'featured'
    const data = await db.collection('MenuList').find({ status: 'sale' }).toArray();

    // Send the data as JSON response
    res.status(200).json(data);

  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});



// Add this route for searching items
app.get('/searchItems', async (req, res) => {
  try {
      const searchTerm = req.query.searchTerm;

      // Connect to the database
      const client = await MongoClient.connect(url, options);
      const db = client.db(dbName);
      const collection = db.collection(collectionMenu);

      // Search for items in the collection
      const searchResults = await collection.find({
          $text: { $search: searchTerm }
      }).toArray();

      // Close the database connection
      client.close();

      res.json(searchResults);
  } catch (error) {
      console.error('Error searching for items:', error);
      res.status(500).json({ error: 'An error occurred while searching for items.' });
  }
});



app.post('/toggleavailability/:name', async (req, res) => {
  const itemName = req.params.name;
  const {
    availability
  } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Update the availability of the menu item in MongoDB
    await db.collection(collectionMenu).updateOne({
      name: itemName
    }, {
      $set: {
        availability
      }
    });

    console.log(`Availability for ${itemName} updated successfully!`);
    res.status(200).json({
      message: `Availability for ${itemName} updated successfully!`
    });
  } catch (err) {
    console.error('Error updating availability:', err);
    res.status(500).json({
      error: 'An error occurred while updating availability.'
    });
  }
});

app.delete('/deletemenu/:name', async (req, res) => {
  const itemName = req.params.name;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Delete the menu item from MongoDB
    await db.collection(collectionMenu).deleteOne({
      name: itemName
    });

    console.log(`Menu item ${itemName} deleted successfully!`);
    res.status(200).json({
      message: `Menu item ${itemName} deleted successfully!`
    });
  } catch (err) {
    console.error('Error deleting menu item:', err);
    res.status(500).json({
      error: 'An error occurred while deleting the menu item.'
    });
  }
});


// Now, you can define your route
app.get('/menufetch2', async (req, res) => {
  try {
    const category = req.query.category;

    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const data = await db.collection('MenuList').find({
      category: category
    }).toArray();

    res.status(200).json(data);
  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/getUserId', (req, res) => {
  try {
    const userId = req.session.passport?.user?.userId;

    if (!userId) {
      return res.status(404).json({
        message: 'User not found in session',
      });
    }

    // Send the userId as a response
    res.json({
      userId,
    });
  } catch (error) {
    console.error('Error retrieving userId:', error);
    res.status(500).json({
      message: 'Internal server error',
    });
  }
});


app.get('/latestOrder', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    } else {
      console.log('Database connection is ready.');
    }

    // Check if the user is logged in and get their user ID from the session
    const userId = req.session.passport?.user?.userId; // Check the session structure

    if (!userId) {
      console.log('User is not logged in.');
      return res.status(401).json({
        error: 'User is not logged in.'
      });
    } else {
      console.log('User ID from session:', userId);
    }

    // Search for the most recent order for the logged-in user
    const latestOrder = await db.collection('CustomerOrders').findOne({
      userId
    }, {
      sort: {
        _id: -1
      }
    });

    if (latestOrder) {
      console.log('Latest order found:', latestOrder);
      res.status(200).json(latestOrder);
    } else {
      console.log('No orders found for the logged-in user.');
      res.status(404).json({
        error: 'No orders found for the logged-in user.'
      });
    }
  } catch (err) {
    console.error('Error fetching latest order:', err);
    res.status(500).json({
      error: 'An error occurred while fetching the latest order.'
    });
  }
});

app.get('/deliveryfee', async (req, res) => {
  try {
    const location = req.query.location;

    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const data = await db.collection('DeliveryFee').find({ Location: location }).toArray();

    if (data.length > 0) {
      // Extract the delivery fee from the first result
      const deliveryfee = data[0].DeliveryFee;

      res.status(200).json({
        deliveryfee
      });
    } else {
      console.log(`No city found with name ${location}.`);
      res.status(404).json({
        error: 'No city found with the provided location.'
      });
    }
  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/fetchdeliveryfee', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch data from MongoDB
    const data = await db.collection('DeliveryFee').find({}).toArray();

    // Send the data as JSON response
    res.status(200).json(data);

  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/updatedeliveryfee', async (req, res) => {
  try {
    // Ensure the database connection is established before updating
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const { location, newDeliveryFee } = req.body;

    // Update the Delivery Fee in the database
    const result = await db.collection('DeliveryFee').updateOne(
      { Location: location },
      { $set: { DeliveryFee: newDeliveryFee } }
    );

    if (result.modifiedCount === 1) {
      res.status(200).json({ message: 'Delivery Fee updated successfully.' });
    } else {
      res.status(404).json({ error: 'Location not found.' });
    }
  } catch (err) {
    console.error('Error updating Delivery Fee:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/checkRestaurantState', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch the restaurant state from MongoDB
    const restaurantState = await db.collection('RestaurantState').findOne({});

    if (restaurantState) {
      res.status(200).json({ state: restaurantState.state });
    } else {
      // Assuming that your document has a 'state' field, replace it with the actual field name
      res.status(404).json({ error: 'Restaurant state not found' });
    }
  } catch (err) {
    console.error('Error fetching data from MongoDB:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/updateRestaurantState', async (req, res) => {
  try {
    // Ensure the database connection is established before updating
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const { state } = req.body;

    // Since there's only one document, you can update it without specifying an identifier
    const result = await db.collection('RestaurantState').updateOne(
      {},
      { $set: { state: state } }
    );

    if (result.modifiedCount === 1) {
      // The document was updated successfully
      res.status(200).json({ message: 'Restaurant state updated successfully' });
    } else {
      // The document was not found or not updated
      res.status(404).json({ error: 'Restaurant state not found or not updated' });
    }
  } catch (err) {
    console.error('Error updating Restaurant state:', err);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/allOrders', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    } else {
      console.log('Database connection is ready.');
    }

    // Check if the user is logged in and get their username from the session
    const userId = req.session.passport.user.userId; // Check the session structure

    if (!userId) {
      console.log('User is not logged in.');
      return res.status(401).json({
        error: 'User is not logged in.'
      });
    } else {
      console.log('UserId from session:', userId);
    }

    // Search for all orders for the logged-in user by their username
    const userOrders = await db.collection('OrderStatus').find({
      userId
    }).toArray();

    if (userOrders && userOrders.length > 0) {
      res.status(200).json(userOrders);
    } else {
      res.status(200).json(userOrders);
      console.log('No orders found for the logged-in user.');
    }
  } catch (err) {
    console.error('Error fetching all orders:', err);
    res.status(500).json({
      error: 'An error occurred while fetching all orders.'
    });
  }
});


app.delete('/deleteOrder/:orderId', async (req, res) => {
  const {
    orderId
  } = req.params;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Delete the order from MongoDB
    const result = await db.collection('CustomerOrders').deleteOne({
      orderId
    });

    if (result.deletedCount === 0) {
      console.log('No order found with the provided orderId.');
      return res.status(404).json({
        error: 'No order found with the provided orderId.'
      });
    }

    console.log('Order deleted successfully.');
    res.status(200).json({
      message: 'Order deleted successfully.'
    });
  } catch (err) {
    console.error('Error deleting order from MongoDB:', err);
    res.status(500).json({
      error: 'An error occurred while deleting the order.'
    });
  }
});

/* Delete route */
app.post('/delete', async (req, res) => {
  const {
    username
  } = req.body;

  try {
    // Ensure the database connection is established before deleting
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Construct the delete query
    const deleteQuery = {
      username
    };

    // Delete the document from the personal_info collection
    const result = await db.collection('AdminAccounts').deleteOne(deleteQuery);

    if (result.deletedCount > 0) {
      console.log('Document deleted successfully.');
      res.status(200).json({
        message: 'Document deleted successfully!'
      });
    } else {
      console.log('No document found with the provided username.');
      res.status(404).json({
        error: 'No document found with the provided username.'
      });
    }
  } catch (err) {
    console.error('Error deleting document:', err);
    res.status(500).json({
      error: 'An error occurred while deleting the document.'
    });
  }
});

app.post('/confirmOrder', async (req, res) => {
  const {
    userId,
    orderId,
    cartItems,
  } = req.body;

  try {
    if (!userId) {
      return res.status(401).json({
        error: 'User not authenticated.'
      });
    }

    // Ensure the database connection is established before saving the data
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    customerDiscount = 0.00
    // Save the orderId, cartItems, and price as a single document in MongoDB
    const result = await db.collection('CustomerOrders').insertOne({
      userId,
      orderId,
      cartItems,
      customerDiscount
    });

    console.log('Order data saved to MongoDB:', result.insertedId);
    res.status(200).json({
      message: "Order confirmed proceeding to transaction"
    });
  } catch (err) {
    console.error('Error saving order data to MongoDB:', err);
    res.status(500).json("An error occurred while ordering");
  }
});

app.post('/updateDiscount', async (req, res) => {
  const {
    orderId,
    customerDiscount
  } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    const updateQuery = {
      orderId
    };
    const updateValues = {
      $set: {
        customerDiscount
      }
    };

    const result = await db.collection('CustomerOrders').updateOne(updateQuery, updateValues);

    if (result.matchedCount > 0) {
      console.log('Delivery status updated successfully.');
      res.status(200).json({
        message: 'Delivery status updated successfully!'
      });
    } else {
      console.log('No order found with the provided orderId.');
      res.status(404).json({
        error: 'No order found with the provided orderId.'
      });
    }
  } catch (err) {
    console.error('Error updating delivery status:', err);
    res.status(500).json({
      error: 'An error occurred while updating the delivery status.'
    });
  }
});

app.set('view engine', 'ejs');

const cN = 'CustomerOrders'; // Replace with your collection name

async function connectToDatabase() {
  const client = await MongoClient.connect(url, {
    useUnifiedTopology: true
  });
  db = client.db(dbName);
}

app.post('/storeOrder', async (req, res) => {
  const {
    userId,
    orderId,
    items,
    location,
    discount,
    totalprice,
    paymentmethod,
    deliverystatus,
    specialinstruction,
  } = req.body;

  try {
    // Ensure the database connection is established before storing the data
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch user details from the UserAccounts collection
    const user = await db.collection('UserAccounts').findOne({ userId });

    if (!user) {
      console.log('User not found in UserAccounts collection.');
      return res.status(404).json({
        error: 'User not found.'
      });
    }

    // Extract the username and phone number from the user document
    const { username, phone } = user;

    // Create a BSON date from the orderDate received from the client
    const orderDate = new Date(); // Replace with the appropriate orderDate

    // Save the order details as a single document in MongoDB
    const result = await db.collection('OrderStatus').insertOne({
      userId,
      orderId,
      username,
      items,
      phone,
      location,
      discount,
      totalprice,
      paymentmethod,
      deliverystatus,
      orderDate,
      specialinstruction,
    });

    console.log('Order data saved to MongoDB:', result.insertedId);

    // Send a success response to the client
    res.status(200).json({
      orderId: result.insertedId
    });
  } catch (err) {
    console.error('Error storing order data to MongoDB:', err);
    res.status(500).json("An error occurred while storing the order data.");
  }
});

// Handle Bux Checkout API
app.post('/open/checkout/', async (req, res) => {
  const buxAPIKey = '062e92d1b56ea9dae98638fcb456828f'; // Replace with your Bux API Key

  try {
    const buxRequest = req.body; // The request body contains the data for Bux Checkout
    console.log("it got here", buxRequest);

    const buxCheckoutResponse = await fetch('https://api.bux.ph/v1/api/sandbox/open/checkout/', { // Replace with the actual Bux API URL
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': buxAPIKey,
      },
      body: JSON.stringify(buxRequest),
    });

    console.log("it got here2", buxCheckoutResponse);

    if (buxCheckoutResponse.ok) {
      const buxData = await buxCheckoutResponse.json();
      console.log("Bux Data:", buxData); // Log the entire response
      const buxCheckoutUrl = buxData.checkout_url;

      res.status(200).json({ url: buxCheckoutUrl });
    } else {
      console.error('Error generating Bux checkout URL.');
      res.status(500).json({ error: 'Error occurred while generating the Bux checkout URL.' });
    }
  } catch (error) {
    console.error('Error during Bux Checkout API:', error);
    res.status(500).json({ error: 'An error occurred during the Bux Checkout process.' });
  }
});

// Handle Bux postback notifications
app.post('/notification_url', async (req, res) => {
  const buxAPIKey = 'your_api_key'; // Replace with your Bux API Key
  const apiSecret = 'bfeda2620b32'; // Replace with your Bux API Secret

  console.log('it got here');
  try {
    const { req_id, client_id, status, signature } = req.body;

    // Verify the signature to ensure the postback is authentic
    const calculatedSignature = sha1(`${req_id}${status}${apiSecret}`);
    if (signature !== calculatedSignature) {
      console.error('Invalid postback signature');
      return res.status(400).send('Invalid postback signature');
    }

    // Now you can update your system based on the payment status (status variable)
    if (status === 'Paid') {
      // Payment was successful, handle it here
      // You can use req_id to identify the order or transaction
      console.log('Payment successful for req_id:', req_id);

      // Add your code to update the order status or perform other actions here
    } else {
      // Payment was not successful
      console.log('Payment not successful for req_id:', req_id);

      // Add your code to handle failed payments here
    }

    // Respond to Bux with a success status
    res.status(200).send('OK');
  } catch (error) {
    console.error('Error handling Bux postback:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/ordersearch', async (req, res) => {
  try {
    // Ensure the database connection is established before searching
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Search for orders with "Delivered" delivery status
    const deliveredOrders = await db.collection('OrderStatus').find({ deliverystatus: "Delivered" }).toArray();

    if (deliveredOrders && deliveredOrders.length > 0) {
      console.log('Delivered orders found:', deliveredOrders);

      // Create a new array to store the individual items
      const formattedOrders = [];

      // Iterate through each delivered order and split the items
      deliveredOrders.forEach(order => {
        order.items.forEach(item => {
          // Create a new order object with individual item details
          const formattedOrder = {
            orderId: order.orderId,
            userId: order.userId,
            username: order.username,
            itemName: item.name,
            itemQuantity: item.quantity,
            itemPrice: item.price,
            phone: order.phone,
            location: order.location,
            deliveryfee: order.totalprice.DeliveryFee,
            discount: order.totalprice.Discount,
            totalprice: order.totalprice.Total,
            paymentmethod: order.paymentmethod,
            deliverystatus: order.deliverystatus,
            orderDate: order.orderDate,
          };
          formattedOrders.push(formattedOrder);
        });
      });

      res.status(200).json(formattedOrders);
    } else {
      console.log('No delivered orders found.');
      res.status(404).json({
        error: 'No delivered orders found.'
      });
    }
  } catch (err) {
    console.error('Error searching for delivered orders:', err);
    res.status(500).json({
      error: 'An error occurred while searching for delivered orders.'
    });
  }
});

function formatReport(orders) {
  let formattedReport = `
  <style>
      table {
        max-width: 80%; /* Set a maximum width for the table */
        margin: 0; /* Reset margin to zero */
        border-collapse: collapse;
        background-color: white;
        font-family: Arial, sans-serif;
      }

      th, td {
        padding: 8px;
        text-align: left;
        border: 1px solid #dddddd;
      }

      th {
        background-color: #00356e;
        color: white;
      }

      tr:nth-child(even) {
        background-color: #f2f2f2;
      }
    </style>
    <div class="report-container">
    <table style="margin-left: 0;"> <!-- Add margin-left: 0; to left-align the table -->
        <tr>
          <th>OrderID</th>
          <th>UserID</th>
          <th>Username</th>
          <th>Item Name</th>
          <th>Item Quantity</th>
          <th>Item Price</th>
          <th>Phone</th>
          <th>Location</th>
          <th>Delivery Fee</th>
          <th>Discount</th>
          <th>Total Price</th>
          <th>Delivery Status</th>
          <th>Payment Method</th>
          <th>Order Date</th>
        </tr>`;

  orders.forEach((order) => {
    const items = order.items || [];
    if (items.length === 0) {
      // Handle orders with no items (if needed)
      // You can skip this order or add a row with a message indicating no items.
    } else {
      items.forEach((item, index) => {
        formattedReport += '<tr>';
        if (index === 0) {
          const totalPrice = items.reduce((total, item) => total + (item.price * item.quantity), 0).toFixed(2);

          const formattedOrderDate = new Date(order.orderDate).toLocaleString('en-US', {
            timeZone: 'Asia/Manila',
            year: 'numeric',
            month: 'numeric',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
          });

          formattedReport += `<td>${order.orderId || ''}</td><td>${order.userId || ''}</td><td>${order.username || ''}</td><td>${item.name || ''}</td><td>${item.quantity || ''}</td>
          <td>Php ${(item.price || 0).toFixed(2)}</td><td>${order.phone || ''}</td><td>${order.location || ''}</td><td>Php ${order.totalprice.DeliveryFee}</td>
          <td>Php ${order.totalprice.Discount}</td><td>Php ${order.totalprice.Total}</td><td>Delivered</td><td>${order.paymentmethod || ''}</td><td>${formattedOrderDate}</td>`;
        } else {
          // For additional items in the same order, leave Delivery Status and Payment Method cells empty.
          formattedReport += `<td>${order.orderId || ''}</td><td>${order.username || ''}</td><td>${item.name || ''}</td><td>${item.quantity || ''}</td><td>Php ${(item.price || 0).toFixed(2)}</td><td>${order.phone || ''}</td><td>${order.location || ''}</td><td></td><td></td><td></td><td></td>`;
        }
        formattedReport += '</tr>';
      });
    }
  });

  formattedReport += '</table>';
  formattedReport += '</div>'; // Close the container
  return formattedReport;
}


app.get('/generateDailyReport', async (req, res) => {
  try {
    const currentDate = new Date();
    const twentyFourHoursAgo = new Date(currentDate - 24 * 60 * 60 * 1000); // Subtract 24 hours
    const dailyOrders = await db
      .collection('OrderStatus')
      .find({
        orderDate: { $gte: twentyFourHoursAgo, $lte: currentDate },
        deliverystatus: 'Delivered' // Only include delivered orders
      })
      .toArray();

    // Format dailyOrders as needed for the report
    const formattedReport = formatReport(dailyOrders);

    if (dailyOrders.length === 0) {
      return res.status(404).json({ error: 'No sales were recorded for today.' });
    }

    res.status(200).send(formattedReport);
  } catch (err) {
    console.error('Error generating daily report:', err);
    res.status(500).json({
      error: 'Error generating daily report.'
    });
  }
});



app.get('/generateWeeklyReport', async (req, res) => {
  try {
    const currentDate = new Date();
    const sevenDaysAgo = new Date(currentDate - 7 * 24 * 60 * 60 * 1000); // Subtract 7 days
    const weeklyOrders = await db
      .collection('OrderStatus')
      .find({
        orderDate: { $gte: sevenDaysAgo, $lte: currentDate },
        deliverystatus: 'Delivered' // Only include delivered orders
      })
      .toArray();

    // Format weeklyOrders as needed for the report
    const formattedReport = formatReport(weeklyOrders);

    res.status(200).send(formattedReport);
  } catch (err) {
    console.error('Error generating weekly report:', err);
    res.status(500).json({
      error: 'No sales were recorded this week.'
    });
  }
});

app.get('/generateMonthlyReport', async (req, res) => {
  try {
    const currentDate = new Date();
    const startOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const monthlyOrders = await db
      .collection('OrderStatus')
      .find({
        orderDate: { $gte: startOfMonth, $lte: currentDate },
        deliverystatus: 'Delivered' // Only include delivered orders
      })
      .toArray();

    // Format monthlyOrders as needed for the report
    const formattedReport = formatReport(monthlyOrders);

    res.status(200).send(formattedReport);
  } catch (err) {
    console.error('Error generating monthly report:', err);
    res.status(500).json({
      error: 'No sales were recorded for this month'
    });
  }
});

app.get('/generateYearlyReport', async (req, res) => {
  try {
    const currentDate = new Date();
    const startOfYear = new Date(currentDate.getFullYear(), 0, 1);
    const yearlyOrders = await db
      .collection('OrderStatus')
      .find({
        orderDate: { $gte: startOfYear, $lte: currentDate },
        deliverystatus: 'Delivered' // Only include delivered orders
      })
      .toArray();

    // Format yearlyOrders as needed for the report
    const formattedReport = formatReport(yearlyOrders);

    res.status(200).send(formattedReport);
  } catch (err) {
    console.error('Error generating yearly report:', err);
    res.status(500).json({
      error: 'No sales were recorded for this year'
    });
  }
});

app.get('/getPassword', isAuthenticated, async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const user = req.user; // Assuming you have stored user information in the session

      if (user) {
        // Access the user's email or other identifier
        const email = user.email;

        // Query the database to get the user's hashed password
        const userAccount = await db.collection(collectionName).findOne({ email });

        if (userAccount) {
          const hashedPasswordFromDB = userAccount.password; // Get the hashed password from the database

          const enteredPassword = 'PasswordEnteredByUser'; // This is the password entered by the user

          bcrypt.compare(enteredPassword, hashedPasswordFromDB, (err, isPasswordMatch) => {
            if (err) {
              console.error('Error comparing passwords:', err);
              res.status(500).json({ success: false, error: 'Error comparing passwords.' });
            } else if (isPasswordMatch) {
              // Passwords match, you can send the hashed password (or any other response you need)
              res.status(200).json({ success: true, password: hashedPasswordFromDB });
            } else {
              // Passwords do not match
              res.status(401).json({ success: false, error: 'Passwords do not match.' });
            }
          });
        } else {
          console.log('User account not found in the database.');
          res.status(404).json({ success: false, error: 'User account not found in the database.' });
        }
      } else {
        console.log('No user information in the session.');
        res.status(404).json({ success: false, error: 'No user information in the session.' });
      }
    } else {
      console.log('User is not authenticated.');
      res.status(401).json({ success: false, error: 'User is not authenticated.' });
    }
  } catch (error) {
    console.error('Error retrieving user password:', error);
    res.status(500).json({ success: false, error: 'An error occurred while retrieving the user password.' });
  }
});


app.get('/profileData', isAuthenticated, async (req, res) => {
  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Retrieve the user's information based on their session (you may use req.user or user ID)
    const userId = req.user.userId;

    const user = await db.collection(collectionName).findOne({ userId });

    if (user) {
      // Respond with the user's information
      const { username, email, phone, password } = user;
      res.status(200).json({ username, email, phone, password });
    } else {
      console.log('User not found in the usersaccount database.');
      res.status(404).json({ error: 'User not found in the database' });
      
    }
  } catch (error) {
    console.error('Error fetching user profile data:', error);
    res.status(500).json({ error: 'An error occurred while fetching user data.' });
  }
});

app.use(express.json());


app.get('/get-user-id', async (req, res) => {
  const username = req.query.username; // Get the username from the request

  // Query your database to retrieve the userId based on the username
  // Replace this with your actual database query
  const userId = await db.collection(collectionName).findOne({ username });

  if (userId) {
    res.status(200).json({ userId });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

app.use(express.urlencoded({ extended: false })); // Add this middleware to parse form data

app.post('/update-profile', async (req, res) => {
  const { userId, username, email, phone, password } = req.body;

  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch the user's current data from the database
    const user = await db.collection(collectionName).findOne({ userId });

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
      });
    }

    const updates = {};
    let fieldsUpdated = 0;

    if (username) {
      updates.username = username;
      fieldsUpdated++;
    }
    if (email) {
      updates.email = email;
      fieldsUpdated++;
    }
    if (phone) {
      updates.phone = phone;
      fieldsUpdated++;
    }
    if (password) {
      // Hash and update the password
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.password = hashedPassword;
      fieldsUpdated++;
    }

    if (fieldsUpdated !== 1) {
      return res.status(400).json({
        error: 'You must update exactly one field at a time.',
      });
    }

    const updateResult = await db.collection(collectionName).updateOne({ userId }, { $set: updates });

    if (updateResult.modifiedCount === 1) {
      // Update the session data with the new profile information
      const userSession = req.session;

      if (username) {
        userSession.passport.user.username = username;
      }
      if (email) {
        userSession.passport.user.email = email;
      }
      if (phone) {
        userSession.passport.user.phone = phone;
      }

      return res.json({ message: 'Profile updated successfully' });
    } else {
      console.log('Profile update did not modify any records.');
      return res.status(500).json({ error: 'Profile update failed' });
    }
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'An error occurred while updating the profile' });
  }
});


app.get('/get-user/:userId', async (req, res) => {
  const { userId } = req.params; // Use req.params.userId to access the userId

  try {
    // Retrieve user data from the UsersAccount database based on userId
    const user = await db.collection('UserAccounts').findOne({ userId });

    if (user) {
      // Display the name, email, and phone in the console log
      console.log('Name:', user.username);
      console.log('Email:', user.email);
      console.log('Phone:', user.phone);

      // Respond with the user data
      res.status(200).json(user);
      // On the server
      res.status(200).json({ message: 'Profile updated successfully' });

    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'An error occurred while fetching user data' });
  }
});

app.post('/update-password', async (req, res) => {
  const { userId, currentPassword, newPassword } = req.body;
  console.log(userId,currentPassword,newPassword);
  try {
    if (!db) {
      console.log('Database connection is not established yet.');
      return res.status(500).json({
        error: 'Database connection is not ready.'
      });
    }

    // Fetch the user's current data from the database
    const user = await db.collection(collectionName).findOne({ userId });

    // Verify the current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Hash and update the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    const updateResult = await db.collection(collectionName).updateOne(
      { userId },
      { $set: { password: hashedPassword } }
    );

    if (updateResult.modifiedCount === 1) {
      // Password update successful
      res.status(200).json({ message: 'Password updated successfully' });
    } else {
      console.log('Password update did not modify any records.');
      res.status(500).json({ error: 'Password update failed' });
    }
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server and connect to the database
connectToDatabase()
  .then(() => {
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });