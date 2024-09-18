import crypto from 'node:crypto'
import DBLocal from 'db-local'
import bcrypt from 'bcrypt'

import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('user', {
  _id: { type: String, require: true },
  username: { type: String, require: true },
  password: { type: String, require: true }
})

export class UserRepository {
  static async create({ username, password }) {
    // 1. Validar username (opcional: usar zod)
    Validation.username(username)
    Validation.password(password)
    // 2. Asegurarse que el username no existe

    const user = User.findOne({ username })
    if (user) throw new Error('username already exists')

    const id = crypto.randomUUID()

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return {
      id: id,
      username: username
    }
  }

  static async login({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('username does not exists')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('password is invalid')

    // const { password: _, ...publicUser } = user
    // return publicUser
    return {
      username: user.username
    }
  }
}

class Validation {
  static username(username) {
    // 1. Validar username (opcional: usar zod)
    if (typeof username !== 'string') {
      throw new Error('username must be a string')
    }
    if (username.length < 3) {
      throw new Error('username must be at least 3 characters long')
    }
  }

  static password(password) {
    if (typeof password !== 'string') {
      throw new Error('username must be a string')
    }
    if (password.length < 6) {
      throw new Error('username must be at least 6 characters long')
    }
  }
}
