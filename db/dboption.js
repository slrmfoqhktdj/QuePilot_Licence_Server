require('dotenv').config({ path:'../.env'});

const DB_HOST = process.env.DATABASE_HOST
const DB_PORT = process.env.DATABASE_PORT
const DB_USER = process.env.DATABASE_USER
const DB_PASSWORD = process.env.DATABASE_PASSWORD
const DB_NAME = process.env.DATABASE_NAME


// const dbconfig = {
//         host:DB_HOST,
//         port:DB_PORT,
//         user:DB_USER,
//         password:DB_PASSWORD,
//         database:DB_NAME,
//         dateStrings:true,    //dateStrings: 날짜 유형(TIMESTAMP, DATETIME, DATE)을 JavaScript Date 객체로 확장하는 대신 문자열로 반환하도록 합니다. (기본값: 거짓)
//         connectionLimit:5
// }

const sessionconfig = {
        host:DB_HOST,
        port:DB_PORT,
        user:DB_USER,
        password:DB_PASSWORD,
        database:DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        timezone: '+00:00',
        dateStrings: true,
}

module.exports = {
        // DB_HOST,
        // DB_PORT, 
        // DB_USER, 
        // DB_PASSWORD, 
        // DB_NAME,
        // dbconfig,
        sessionconfig
}