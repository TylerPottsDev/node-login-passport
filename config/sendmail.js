const nodemailer = require('nodemailer');
require("dotenv").config();

const config = {
    host: 'smtp.office365.com',
    port: 587,
    auth: {
        user: process.env.SMTP_USERNAME,
        pass: process.env.SMTP_PASSWORD
    }
};

module.exports = {
    sendEmail
};

async function sendEmail({ from, to, subject, html }) {
    const transporter = nodemailer.createTransport(config);
    await transporter.sendMail({ from, to, subject, html });
}

