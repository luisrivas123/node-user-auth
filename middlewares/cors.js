import cors from 'cors'

const ACCEPTED_ORIGINS = ['http://localhost:5173', 'http://localhost:5174']

export const corsMiddleware = ({ acceptedOrigins = ACCEPTED_ORIGINS } = {}) =>
  cors({
    origin: (origin, callback) => {
      if (acceptedOrigins.includes(origin) || !origin) {
        return callback(null, true)
      }

      return callback(new Error('Not allow by CORS'))
    },
    credentials: true
  })
