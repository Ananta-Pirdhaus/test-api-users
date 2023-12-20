import express, { NextFunction, Request, Response } from 'express';
import { PrismaClient } from "@prisma/client";
import bcrypt from 'bcrypt';
import jwt, {JwtPayload} from 'jsonwebtoken';
import * as dotenv from 'dotenv';
import {google} from 'googleapis';

const app = express();
const PORT = 5000;
const prisma = new PrismaClient();

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    'http://localhost:5000/auth/google/callback'
);

const scopes = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

const authorizationUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    include_granted_scopes: true,
})

app.use(express.json())

interface UserData {
    id: string;
    name: string;
}

interface ValidationRequest extends Request {
    userData: UserData
}

const accessValidation = (req: Request, res: Response, next: NextFunction) => {
  const validationReq = req as ValidationRequest;
  const { authorization } = validationReq.headers;

  console.log("Authorization Header:", authorization);

  if (!authorization) {
    return res.status(401).json({
      message: "Token diperlukan",
    });
  }

  const token = authorization.split(" ")[1];
  const secret = process.env.JWT_SECRET!;

  console.log("Extracted Token:", token);

  try {
    const jwtDecode = jwt.verify(token, secret);

    if (typeof jwtDecode !== "string") {
      validationReq.userData = jwtDecode as UserData;
    }
    console.log("Decoded JWT:", jwtDecode);
  } catch (error) {
    console.error("Error verifying token:", error);
    return res.status(401).json({
      message: "Unauthorized",
    });
  }
  next();
};


// GOOGLE Login
app.get('/auth/google', (req, res) => {
    res.redirect(authorizationUrl);
})

// GOOGLE callback login
app.get('/auth/google/callback', async (req, res) => {
    const {code} = req.query

    const {tokens} = await oauth2Client.getToken(code as string);

    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({
        auth: oauth2Client,
        version: 'v2'
    })

    const {data} = await oauth2.userinfo.get();

    if(!data.email || !data.name){
        return res.json({
            data: data,
        })
    }

    let user = await prisma.users.findUnique({
        where: {
            email: data.email
        }
    })

    if(!user){
        user = await prisma.users.create({
            data: {
                name: data.name,
                email: data.email,
            }
        })
    }

    const payload = {
        id: user?.id,
        name: user?.name,
    }

    const secret = process.env.JWT_SECRET!;

    const expiresIn = 60 * 60 * 1;

    const token = jwt.sign(payload, secret, {expiresIn: expiresIn})

    // return res.redirect(`http://localhost:3000/auth-success?token=${token}`)

    return res.json({
      data: {
        id: user.id,
        name: user.name,
        token: token,
      },
    });

})

// REGISTER
app.use("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if the required fields are present in the request body
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Name, email, and password are required fields" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await prisma.users.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    res.json({
      message: "User created successfully",
      user: result,
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// REGISTER nonaktifkan untuk Oauth

// app.use('/register', async (req, res) => {
//     const { name, email, password } = req.body;

//     // Men-generate hashed password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     try {
//         // Menyimpan user ke database dengan hashed password
//         const result = await prisma.users.create({
//             data: {
//                 name,
//                 email,
//                 password: hashedPassword,
//             }
//         });

//         res.json({
//             message: 'user created'
//         });
//     } catch (error) {
//         console.error('Error creating user:', error);
//         res.status(500).json({
//             message: 'Internal Server Error'
//         });
//     }
// });


// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Ensure email is provided
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const user = await prisma.users.findUnique({
      where: {
        email: email,
      },
    });

    // Check if the user exists
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Check if the password is set
    if (!user.password) {
      return res.status(404).json({
        message: "Password not set",
      });
    }

    // Check if the provided password is valid
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      // Generate JWT token
      const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
        // Add additional user properties if needed
      };

      const secret = process.env.JWT_SECRET || "your-secret-key"; // Replace with your secret key
      const expiresIn = 60 * 60 * 1; // 1 hour

      const token = jwt.sign(payload, secret, { expiresIn: expiresIn });

      return res.json({
        data: {
          id: user.id,
          name: user.name,
          email: user.email,
          token: token,
          // Add additional user properties if needed
        },
      });
    } else {
      return res.status(403).json({
        message: "Wrong password",
      });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

// CREATE
app.post('/users/validations', accessValidation, async (req, res, next) => {
    const {name, email, } = req.body;

    const result = await prisma.users.create({
        data: {
            name: name,
            email: email, 
        }
    }) 
    res.json({
        data: result,
        message: `User created`
    })
})

// Sebelumnya
// app.get('/users', accessValidation, async (req, res) => {
app.get('/users', async (req, res) => {
    const result = await prisma.users.findMany({
        select: {
            id: true,
            name: true,
            email: true,
        }
    });
    res.json({
        data: result,
        message: 'User list'
    })
});

// getbyId
app.get("/users/:id", async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const user = await prisma.users.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
      },
    });

    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    res.json({
      data: user,
      message: "User details",
    });
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// READ
app.get('/users',accessValidation, async (req, res) => {
    const result = await prisma.users.findMany({
        select: {
            id: true,
            name: true,
            email: true,
        }
    });
    res.json({
        data: result,
        message: 'User list'
    })
})

// UPDATE
app.patch('/users/:id', accessValidation, async (req, res) => {
    const {id} = req.params
    const {name, email, } = req.body
    
    const result = await prisma.users.update({
        data: {
            name: name,
            email: email,
        },
        where: {
            id: Number(id)
        }
    })
    res.json({
        data: result,
        message: `User ${id} updated`
    })
})

// DELETE
app.delete('/users/:id', accessValidation, async (req, res) => {
    const {id} = req.params;

    const result = await prisma.users.delete({
        where: {
            id: Number(id)
        }
    })
    res.json({
        message: `User ${id} deleted`
    })
})

app.listen(PORT, () => {
    console.log(`Server running in PORT: ${PORT}`);
})