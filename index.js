import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

import { corsMiddleware } from './middlewares/cors.js'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

app.use(corsMiddleware())
app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
    console.log(data)
  } catch {}

  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  // res.render('example', { username: 'Luis' })
  res.render('index', user)

  // try {
  //   const data = jwt.verify(token, SECRET_JWT_KEY)
  //   res.render('index', data)
  // } catch (error) {
  //   res.render('index')
  // }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_JWT_KEY,
      {
        expiresIn: '1m'
      }
    )

    res
      .cookie('access_token', token, {
        httpOnly: true, // LA cookie solo se puede acceder en el servidor
        secure: process.env.NODE_ENV === 'production', // La cookie solo se pudede acceder en https
        sameSite: 'strict', // la coockie solo se puede acceder en el mismo dominio
        maxAge: 1000 * 60 * 60 // la cookie tiene un tiempo de validez de una hora
      })
      .send({ user, token })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body

  try {
    const user = await UserRepository.create({ username, password })
    res.send({ user })
  } catch (error) {
    res.status(400).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  res.clearCookie('access_token').json({ message: 'Logout successful' })
})

app.get('/check-auth', (req, res) => {
  // const token = req.cookies.access_token;

  const { user } = req.session

  if (!user) return res.status(401).json({ message: 'Unauthorized' })
  res.status(200).json({ user: user })

  // try {
  //     const decoded = jwt.verify(token, 'your_secret_key'); // Verifica el token con tu clave secreta
  //     return res.status(200).json({ user: decoded });
  // } catch (err) {
  //     return res.status(401).json({ message: 'Unauthorized' });
  // }
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  console.log(user)

  if (!user) return res.status(403).send('Access not authorized')
  res.render('protected', user)

  // try {
  //   const data = jwt.verify(token, SECRET_JWT_KEY)
  //   res.render('protected', data)
  // } catch (error) {
  //   res.status(401).send('Access not authorized')
  // }
})

app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`)
})
