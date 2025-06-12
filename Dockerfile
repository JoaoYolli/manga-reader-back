# Etapa 1: instalación de dependencias

FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY . .

RUN npm install

RUN npm audit fix

# Etapa 2: empaquetado de la aplicación
FROM node:20-alpine

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app ./

EXPOSE 3000

CMD ["npm", "start"]
