require("dotenv").config();
const axios = require('axios');

const secretKey = process.env.RECAPTCHA_SECRET; 
   
const recaptchaVerification = async (req, res, next) => {  
    try {
        const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
            params: {
                secret: secretKey,
                response: req.body['g-recaptcha-response']
            }
        });

        //console.log(response.data.score);

        if (response.data.success && response.data.score >= 0.5) {
            next();
        }
        
        else {
            res.redirect('login?error=true')
        }
    } catch (error) {
        // Error occurred during reCAPTCHA verification
        console.log("An error occurred with captcha verification: "+error);
        res.redirect('login?error=true');
    }
}

module.exports = {
    recaptchaVerification
};
